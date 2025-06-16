/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package reporter implements a central reporting mechanism for various data types. The provided
// information is cached before it is sent in a configured interval to the destination.
// It may happen that information get lost if reporter can not send the provided information
// to the destination.
//
// As we must convert our internal types, e.g. libpf.TraceHash, into primitive types, before sending
// them over the wire, the question arises as to where to do this? In this package we favor doing
// so as close to the actual 'send' over the network as possible. So, the ReportX functions that
// clients of this package make use of try to accept our types, push them onto a reporting queue,
// and then do the conversion in whichever function flushes that queue and sends the data over
// the wire.
package reporter

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/otel-profiling-agent/libpf"
)

// HostMetadata holds metadata about the host.
type HostMetadata struct {
	Metadata  map[string]string
	Timestamp uint64
}

type Config struct {
	// CollAgentAddr defines the destination of the backend connection
	CollAgentAddr string

	// MaxRPCMsgSize defines the maximum size of a gRPC message.
	MaxRPCMsgSize int

	// ExecMetadataMaxQueue defines the maximum size for the queue which holds
	// data of type collectionagent.ExecutableMetadata.
	ExecMetadataMaxQueue uint32
	// CountsForTracesMaxQueue defines the maximum size for the queue which holds
	// data of type libpf.TraceAndCounts.
	CountsForTracesMaxQueue uint32
	// MetricsMaxQueue defines the maximum size for the queue which holds
	// data of type collectionagent.Metric.
	MetricsMaxQueue uint32
	// FramesForTracesMaxQueue defines the maximum size for the queue which holds
	// data of type libpf.Trace.
	FramesForTracesMaxQueue uint32
	// FrameMetadataMaxQueue defines the maximum size for the queue which holds
	// data of type collectionagent.FrameMetadata.
	FrameMetadataMaxQueue uint32
	// HostMetadataMaxQueue defines the maximum size for the queue which holds
	// data of type collectionagent.HostMetadata.
	HostMetadataMaxQueue uint32
	// FallbackSymbolsMaxQueue defines the maximum size for the queue which holds
	// data of type collectionagent.FallbackSymbol.
	FallbackSymbolsMaxQueue uint32
	// Disable secure communication with Collection Agent
	DisableTLS bool
	// Number of connection attempts to the collector after which we give up retrying
	MaxGRPCRetries uint32

	SamplesPerSecond uint

	Times Times
}

// GRPCReporter will be the reporter state and implements various reporting interfaces
type GRPCReporter struct {
	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *statsHandlerImpl

	// executableMetadataQueue is a ring buffer based FIFO for *executableMetadata
	execMetadataQueue fifoRingBuffer[*executableMetadata]
	// countsForTracesQueue is a ring buffer based FIFO for *libpf.TraceAndCounts
	countsForTracesQueue fifoRingBuffer[*libpf.TraceAndCounts]
	// metricsQueue is a ring buffer based FIFO for *tsMetric
	metricsQueue fifoRingBuffer[*tsMetric]
	// framesForTracesQueue is a ring buffer based FIFO for *libpf.Trace
	framesForTracesQueue fifoRingBuffer[*libpf.Trace]
	// frameMetadataQueue is a ring buffer based FIFO for *frameMetadata
	frameMetadataQueue fifoRingBuffer[*libpf.FrameMetadata]
	// hostMetadataQueue is a ring buffer based FIFO for collectionagent.HostMetadata.
	hostMetadataQueue fifoRingBuffer[*HostMetadata]
	// fallbackSymbolsQueue is a ring buffer based FIFO for *fallbackSymbol
	fallbackSymbolsQueue fifoRingBuffer[*fallbackSymbol]
}

// Assert that we implement the full Reporter interface.
var _ Reporter = (*GRPCReporter)(nil)

// ReportFramesForTrace implements the TraceReporter interface.
func (r *GRPCReporter) ReportFramesForTrace(trace *libpf.Trace) {
	r.framesForTracesQueue.append(trace)
}

type executableMetadata struct {
	fileID   libpf.FileID
	filename string
	buildID  string
}

// ExecutableMetadata implements the SymbolReporter interface.
func (r *GRPCReporter) ExecutableMetadata(ctx context.Context, fileID libpf.FileID,
	fileName, buildID string) {
	select {
	case <-ctx.Done():
		return
	default:
		r.execMetadataQueue.append(&executableMetadata{
			fileID:   fileID,
			filename: fileName,
			buildID:  buildID,
		})
	}
}

// FrameMetadata implements the SymbolReporter interface.
func (r *GRPCReporter) FrameMetadata(fileID libpf.FileID,
	addressOrLine libpf.AddressOrLineno, lineNumber libpf.SourceLineno, functionOffset uint32,
	functionName, filePath string) {
	r.frameMetadataQueue.append(&libpf.FrameMetadata{
		FileID:         fileID,
		AddressOrLine:  addressOrLine,
		LineNumber:     lineNumber,
		FunctionOffset: functionOffset,
		FunctionName:   functionName,
		Filename:       filePath,
	})
}

// ReportCountForTrace implements the TraceReporter interface.
func (r *GRPCReporter) ReportCountForTrace(traceHash libpf.TraceHash, timestamp libpf.UnixTime32,
	count uint16, comm, podName, containerName string) {
	r.countsForTracesQueue.append(&libpf.TraceAndCounts{
		Hash:          traceHash,
		Timestamp:     timestamp,
		Count:         count,
		Comm:          comm,
		PodName:       podName,
		ContainerName: containerName,
	})
}

type fallbackSymbol struct {
	frameID libpf.FrameID
	symbol  string
}

// ReportFallbackSymbol implements the SymbolReporter interface.
func (r *GRPCReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	r.fallbackSymbolsQueue.append(&fallbackSymbol{
		frameID: frameID,
		symbol:  symbol,
	})
}

type tsMetric struct {
	timestamp uint32
	ids       []uint32
	values    []int64
}

// ReportMetrics implements the MetricsReporter interface.
func (r *GRPCReporter) ReportMetrics(timestamp uint32, ids []uint32, values []int64) {
	r.metricsQueue.append(&tsMetric{
		timestamp: timestamp,
		ids:       ids,
		values:    values,
	})
}

// ReportHostMetadata implements the HostMetadataReporter interface.
func (r *GRPCReporter) ReportHostMetadata(_ map[string]string) {
}

// ReportHostMetadataBlocking implements the HostMetadataReporter interface.
func (r *GRPCReporter) ReportHostMetadataBlocking(_ context.Context,
	_ map[string]string, _ int, _ time.Duration) error {
	return nil
}

// Start sets up and manages the reporting connection to our backend as well as a per data
// type caching mechanism to send the provided information in bulks to the backend.
// Callers of Start should be calling the corresponding Stop() API to conclude gracefully
// the operations managed here.
func Start(_ context.Context, c *Config) (*GRPCReporter, error) {
	r := &GRPCReporter{
		stopSignal: make(chan libpf.Void),
		rpcStats:   newStatsHandler(),
	}

	if err := r.execMetadataQueue.initFifo(c.ExecMetadataMaxQueue,
		"executable metadata"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for executable metadata: %v", err)
	}

	if err := r.countsForTracesQueue.initFifo(c.CountsForTracesMaxQueue,
		"counts for traces"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for tracehash count: %v", err)
	}

	if err := r.metricsQueue.initFifo(c.MetricsMaxQueue,
		"metrics"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for metrics: %v", err)
	}

	if err := r.framesForTracesQueue.initFifo(c.FramesForTracesMaxQueue,
		"frames for traces"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for frames for traces: %v", err)
	}

	if err := r.frameMetadataQueue.initFifo(c.FrameMetadataMaxQueue,
		"frame metadata"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for frame metadata: %v", err)
	}

	if err := r.hostMetadataQueue.initFifo(c.HostMetadataMaxQueue,
		"host metadata"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for host metadata: %v", err)
	}

	if err := r.fallbackSymbolsQueue.initFifo(c.FallbackSymbolsMaxQueue,
		"fallback symbols"); err != nil {
		return nil, fmt.Errorf("failed to setup queue for fallback symbols: %v", err)
	}

	return r, nil
}

// Stop asks all background tasks to exit.
func (r *GRPCReporter) Stop() {
	close(r.stopSignal)
}
