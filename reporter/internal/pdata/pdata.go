// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// Executables stores metadata for executables.
	Executables *lru.SyncedLRU[libpf.FileID, samples.ExecInfo]

	// Frames maps frame information to its source location.
	Frames *lru.SyncedLRU[
		libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo],
	]

	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer
}

func New(samplesPerSecond int, executablesCacheElements, framesCacheElements uint32,
	extra samples.SampleAttrProducer) (*Pdata, error) {
	executables, err :=
		lru.NewSynced[libpf.FileID, samples.ExecInfo](executablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	executables.SetLifetime(ExecutableCacheLifetime) // Allow GC to clean stale items.

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]](
		framesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	frames.SetLifetime(FramesCacheLifetime) // Allow GC to clean stale items.

	return &Pdata{
		samplesPerSecond:    samplesPerSecond,
		Executables:         executables,
		Frames:              frames,
		ExtraSampleAttrProd: extra,
	}, nil
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
	p.Executables.PurgeExpired()
	p.Frames.PurgeExpired()
}
