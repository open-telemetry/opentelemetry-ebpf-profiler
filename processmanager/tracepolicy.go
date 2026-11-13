// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// TraceContext carries origin-scoped trace information. ContextValues alias
// the pooled buffer and are valid only during the call.
type TraceContext struct {
	// Origin is the trace origin ID.
	Origin uint16
	// PID is the process ID (tgid), TID the thread ID.
	PID, TID libpf.PID
	// KTime is the capture time in CLOCK_BOOTTIME nanoseconds, see times.KTime.
	KTime times.KTime
	// Comm is the command name of the captured thread.
	Comm libpf.Comm
	// ContextValues are the origin-specific values; the first, if any, is the
	// primary profile value.
	ContextValues []uint64
}

// TraceHandlerHooks lets probes intercept traces of their origin before
// symbolization or after reporting.
type TraceHandlerHooks interface {
	// PreHandleTrace is called before symbolization; return false to consume
	// the trace.
	PreHandleTrace(ctx *TraceContext) bool

	// PostHandleTrace is called after symbolization and reporting.
	PostHandleTrace(ctx *TraceContext, trace *libpf.Trace)
}

// StubTraceHandlerHooks provides no-op TraceHandlerHooks.
type StubTraceHandlerHooks struct{}

func (StubTraceHandlerHooks) PreHandleTrace(*TraceContext) bool { return true }

func (StubTraceHandlerHooks) PostHandleTrace(*TraceContext, *libpf.Trace) {}

// OriginEntry bundles the profile type metadata and hooks of one origin ID.
type OriginEntry struct {
	// Meta is the profile type metadata for the origin.
	Meta *samples.TypeMetadata

	// Hooks receive the origin's traces; nil defaults to no-op stubs.
	Hooks TraceHandlerHooks
}

// OriginRegistry assigns origin IDs and stores their OriginEntries. It is
// the only source of entries, so dispatched entries always carry hooks.
type OriginRegistry struct {
	// lastID is the most recently assigned origin ID.
	lastID atomic.Uint32

	// entries maps a trace origin (uint16) to its *OriginEntry.
	entries sync.Map
}

// Register validates entry and hands out a fresh origin ID; nil hooks
// default to stubs.
func (r *OriginRegistry) Register(entry *OriginEntry) (uint16, error) {
	if len(entry.Meta.SampleTypes) == 0 {
		return 0, fmt.Errorf("origin registry entry needs at least one sample type")
	}
	if entry.Meta.AppendValues == nil {
		return 0, fmt.Errorf("origin registry entry needs AppendValues")
	}
	if last := r.lastID.Load(); last >= math.MaxUint16 {
		return 0, fmt.Errorf("maximum number of origin registry entries exceeded")
	}
	if entry.Hooks == nil {
		entry.Hooks = StubTraceHandlerHooks{}
	}
	id := uint16(r.lastID.Add(1))
	r.entries.Store(id, entry)
	return id, nil
}

// Lookup returns the OriginEntry for origin, or nil if unknown.
func (r *OriginRegistry) Lookup(origin uint16) *OriginEntry {
	v, ok := r.entries.Load(origin)
	if !ok {
		return nil
	}
	return v.(*OriginEntry)
}
