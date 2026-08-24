// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtimeinfo contributes the process.runtime.name and
// process.runtime.version resource attributes. Knowing a sample came from CPython
// 3.11.4 rather than just "CPython" is what lets that version's standard library
// sources be resolved.
package runtimeinfo // import "go.opentelemetry.io/ebpf-profiler/procmeta/runtimeinfo"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
)

// enricher reports the runtime of a process. Stateless: whether a process is
// already resolved is recorded in its state slot.
type enricher struct{}

// NewEnricher returns a ResourceEnricher contributing the language runtime of a
// process, resolved from the interpreters the profiler attached to it.
func NewEnricher() procmeta.ResourceEnricher {
	return enricher{}
}

func (enricher) ResourceConfig() procmeta.ResourceConfig {
	return procmeta.ResourceConfig{}
}

// resolved marks a process whose runtime has been reported, which is then left
// alone: a process does not swap runtimes, and re-resolving on every sync would let
// the reported one flip as further interpreters attach. An exec needs no handling
// here: the manager drops this marker with the contribution, so the next call
// resolves again.
type resolved struct{}

func (enricher) EnrichResource(req *procmeta.ResourceRequest) (*pcommon.Resource, bool) {
	if _, done := (*req.State).(resolved); done {
		return nil, false
	}

	name, version := selectRuntime(req)
	if name == "" {
		// No interpreter attached yet, or none can report. They are detected as their
		// mappings appear, so a later synchronization may still resolve one.
		return nil, false
	}

	res := pcommon.NewResource()
	res.Attributes().PutStr(string(semconv.ProcessRuntimeNameKey), name)
	if version != "" {
		res.Attributes().PutStr(string(semconv.ProcessRuntimeVersionKey), version)
	}

	*req.State = resolved{}
	return &res, true
}

// selectRuntime picks the runtime to report for a process that may host several: a
// Go binary embedding CPython, or Python calling a JIT-compiled library over FFI.
func selectRuntime(req *procmeta.ResourceRequest) (name, version string) {
	// Smallest (name, version), so a process hosting several keeps reporting the same
	// one instead of flipping with Go's map order and splitting its samples.
	candidates := 0
	for _, inst := range req.Interpreters {
		n, v, ok := inst.RuntimeInfo()
		if !ok {
			continue
		}
		candidates++
		if name == "" || n < name || (n == name && v < version) {
			name, version = n, v
		}
	}
	if candidates < 2 {
		// Nothing to disambiguate: none can report, or exactly one can and it is the
		// answer whichever DSO it came from. Identifying the executable costs a stat,
		// so it waits for an actual choice — a process that never resolves a runtime
		// would otherwise pay for it on every resynchronization.
		return name, version
	}

	// Prefer the top-level runtime: the one whose DSO is the process's own
	// executable. That is what makes a Go binary embedding CPython report "go".
	exeID, err := req.Process.GetExecutableFileIdentifier()
	if err != nil {
		log.Debugf("Failed to identify the executable of PID %d: %v", req.Process.PID(), err)
		return name, version
	}
	if inst, ok := req.Interpreters[exeID]; ok {
		if n, v, ok := inst.RuntimeInfo(); ok {
			return n, v
		}
	}
	return name, version
}
