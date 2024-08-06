/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"context"
	"fmt"
	"sync/atomic"

	"google.golang.org/grpc/stats"

	"github.com/elastic/otel-profiling-agent/libpf/xsync"
)

type StatsHandlerImpl struct {
	// Total number of uncompressed bytes in/out
	numRPCBytesOut atomic.Int64
	numRPCBytesIn  atomic.Int64

	// Total number of on-the-wire (post-compression) bytes in/out
	numWireBytesOut atomic.Int64
	numWireBytesIn  atomic.Int64

	// These two maps aggregate total in/out byte counts under each RPC method name
	rpcBytesOut xsync.RWMutex[map[string]uint64]
	rpcBytesIn  xsync.RWMutex[map[string]uint64]

	// These two maps aggregate total in/out byte counts under each RPC method name
	wireBytesOut xsync.RWMutex[map[string]uint64]
	wireBytesIn  xsync.RWMutex[map[string]uint64]
}

// Make sure that the handler implements stats.Handler.
var _ stats.Handler = (*StatsHandlerImpl)(nil)

// keyRPCTagInfo is the context key for our state.
//
// This is in a global to avoid having to allocate a new string on every call.
var keyRPCTagInfo = "RPCTagInfo"

// NewStatsHandler creates a new statistics handler.
func NewStatsHandler() *StatsHandlerImpl {
	return &StatsHandlerImpl{
		rpcBytesOut:  xsync.NewRWMutex(map[string]uint64{}),
		rpcBytesIn:   xsync.NewRWMutex(map[string]uint64{}),
		wireBytesOut: xsync.NewRWMutex(map[string]uint64{}),
		wireBytesIn:  xsync.NewRWMutex(map[string]uint64{}),
	}
}

// TagRPC implements the stats.Handler interface.
func (sh *StatsHandlerImpl) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, &keyRPCTagInfo, info)
}

// TagConn implements the stats.Handler interface.
func (sh *StatsHandlerImpl) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

// HandleConn implements the stats.Handler interface.
func (sh *StatsHandlerImpl) HandleConn(context.Context, stats.ConnStats) {
}

func rpcMethodFromContext(ctx context.Context) (string, error) {
	tagInfo, ok := ctx.Value(&keyRPCTagInfo).(*stats.RPCTagInfo)
	if !ok {
		return "", fmt.Errorf("missing context key: %v", keyRPCTagInfo)
	}
	return tagInfo.FullMethodName, nil
}

// HandleRPC implements the stats.Handler interface.
func (sh *StatsHandlerImpl) HandleRPC(ctx context.Context, s stats.RPCStats) {
	var wireBytesIn, wireBytesOut, rpcBytesIn, rpcBytesOut int64

	switch s := s.(type) {
	case *stats.InPayload:
		// WireLength is the length of data on wire (compressed, signed, encrypted,
		// with gRPC framing).
		wireBytesIn = int64(s.WireLength)
		// Length is the uncompressed payload data
		rpcBytesIn = int64(s.Length)
	case *stats.OutPayload:
		wireBytesOut = int64(s.WireLength)
		rpcBytesOut = int64(s.Length)
	default:
		return
	}

	method, err := rpcMethodFromContext(ctx)
	if err != nil {
		// If this happens, it's a bug and we should visibly exit (context must contain tag)
		panic(err)
	}

	if wireBytesIn != 0 {
		sh.numWireBytesIn.Add(wireBytesIn)
		sh.numRPCBytesIn.Add(rpcBytesIn)
		wireIn := sh.wireBytesIn.WLock()
		rpcIn := sh.rpcBytesIn.WLock()
		defer sh.wireBytesIn.WUnlock(&wireIn)
		defer sh.rpcBytesIn.WUnlock(&rpcIn)
		(*wireIn)[method] += uint64(wireBytesIn)
		(*rpcIn)[method] += uint64(rpcBytesIn)
	}

	if wireBytesOut != 0 {
		sh.numWireBytesOut.Add(wireBytesOut)
		wireOut := sh.wireBytesOut.WLock()
		rpcOut := sh.rpcBytesOut.WLock()
		defer sh.wireBytesOut.WUnlock(&wireOut)
		defer sh.rpcBytesOut.WUnlock(&rpcOut)
		(*wireOut)[method] += uint64(wireBytesOut)
		(*rpcOut)[method] += uint64(rpcBytesOut)
	}
}

func (sh *StatsHandlerImpl) GetWireBytesOut() int64 {
	return sh.numWireBytesOut.Swap(0)
}

func (sh *StatsHandlerImpl) GetWireBytesIn() int64 {
	return sh.numWireBytesIn.Swap(0)
}

func (sh *StatsHandlerImpl) GetRPCBytesOut() int64 {
	return sh.numRPCBytesOut.Swap(0)
}

func (sh *StatsHandlerImpl) GetRPCBytesIn() int64 {
	return sh.numRPCBytesIn.Swap(0)
}

//nolint:unused
func (sh *StatsHandlerImpl) getMethodRPCBytesOut() map[string]uint64 {
	rpcOut := sh.rpcBytesOut.RLock()
	defer sh.rpcBytesOut.RUnlock(&rpcOut)
	res := make(map[string]uint64, len(*rpcOut))
	for k, v := range *rpcOut {
		res[k] = v
	}
	return res
}

//nolint:unused
func (sh *StatsHandlerImpl) getMethodRPCBytesIn() map[string]uint64 {
	rpcIn := sh.rpcBytesIn.RLock()
	defer sh.rpcBytesIn.RUnlock(&rpcIn)
	res := make(map[string]uint64, len(*rpcIn))
	for k, v := range *rpcIn {
		res[k] = v
	}
	return res
}

//nolint:unused
func (sh *StatsHandlerImpl) getMethodWireBytesOut() map[string]uint64 {
	wireOut := sh.wireBytesOut.RLock()
	defer sh.wireBytesOut.RUnlock(&wireOut)
	res := make(map[string]uint64, len(*wireOut))
	for k, v := range *wireOut {
		res[k] = v
	}
	return res
}

//nolint:unused
func (sh *StatsHandlerImpl) getMethodWireBytesIn() map[string]uint64 {
	wireIn := sh.wireBytesIn.RLock()
	defer sh.wireBytesIn.RUnlock(&wireIn)
	res := make(map[string]uint64, len(*wireIn))
	for k, v := range *wireIn {
		res[k] = v
	}
	return res
}

// Metrics holds the metric counters for the reporter package.
type Metrics struct {
	CountsForTracesOverwriteCount uint32
	ExeMetadataOverwriteCount     uint32
	FrameMetadataOverwriteCount   uint32
	FramesForTracesOverwriteCount uint32
	HostMetadataOverwriteCount    uint32
	MetricsOverwriteCount         uint32
	FallbackSymbolsOverwriteCount uint32
	RPCBytesOutCount              int64
	RPCBytesInCount               int64
	WireBytesOutCount             int64
	WireBytesInCount              int64
}
