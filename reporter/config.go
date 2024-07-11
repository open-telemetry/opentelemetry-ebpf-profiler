/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"time"

	"google.golang.org/grpc"
)

type Config struct {
	// Name defines the name of the agent.
	Name string

	// Version defines the vesion of the agent.
	Version string

	// CollAgentAddr defines the destination of the backend connection.
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
	// Disable secure communication with Collection Agent.
	DisableTLS bool
	// CacheSize defines the size of the reporter caches.
	CacheSize uint32
	// samplesPerSecond defines the number of samples per second.
	SamplesPerSecond int
	// ProjectID is the project ID to be sent to the collection agent.
	ProjectID string
	// HostID is the host ID to be sent to the collection agent.
	HostID uint64

	// Number of connection attempts to the collector after which we give up retrying.
	MaxGRPCRetries uint32

	GRPCOperationTimeout   time.Duration
	GRPCStartupBackoffTime time.Duration
	GRPCConnectionTimeout  time.Duration
	ReportInterval         time.Duration

	// gRPCInterceptor is the client gRPC interceptor, e.g., for sending gRPC metadata.
	GRPCClientInterceptor grpc.UnaryClientInterceptor
}
