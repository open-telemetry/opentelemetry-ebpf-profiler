// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package procmeta provides the extension point for contributing OTel resource
// attributes to a profiled process.
//
// It complements process.MetaEnricher, which collects metadata once when a process
// is first observed. Attributes that resolve later — a memory region published
// after startup, a runtime whose interpreter attaches once its mapping appears —
// need a ResourceEnricher, called on every resynchronization, contributing an
// immutable resource rather than writing to shared metadata.
package procmeta // import "go.opentelemetry.io/ebpf-profiler/procmeta"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// ResourceConfig declares what a ResourceEnricher needs. The zero value asks for
// nothing; new requirements are added as new fields.
type ResourceConfig struct {
	// WantMapping selects the mappings delivered in ResourceRequest.Mappings, nil
	// selecting none. Called for every mapping of every synchronized process, so it
	// must be cheap: no allocation, no syscalls.
	WantMapping func(m *process.RawMapping) bool
}

// ResourceRequest describes a process and what the process manager observed for it
// this synchronization. Valid only for the duration of the EnrichResource call:
// enrichers must not retain it, or anything reachable from it.
type ResourceRequest struct {
	// Process gives access to remote memory, mappings and the executable.
	Process process.Process

	// Mappings holds the mappings selected by ResourceConfig.WantMapping, in
	// /proc/<pid>/maps order.
	Mappings []process.RawMapping

	// Interpreters holds the instances attached to the process, keyed by the on-disk
	// identity of the DSO each was detected in, and is nil until one attaches.
	// Read-only: driving the instances belongs to the process manager.
	Interpreters map[util.OnDiskFileIdentifier]interpreter.Instance

	// State points at the manager's per-process storage slot for this enricher:
	// *State is what the previous call stored, nil on the first. Keep per-process
	// state here rather than in enricher-owned maps, so it is dropped with the
	// process. Storage, not a lifecycle — the value is dropped with no teardown
	// call, so it must not own anything needing an explicit release.
	State *any
}

// ResourceEnricher contributes OTel resource attributes for a process.
type ResourceEnricher interface {
	// ResourceConfig returns the enricher's requirements. It is called once, when
	// the enricher is registered.
	ResourceConfig() ResourceConfig

	// EnrichResource returns the enricher's contribution for the process described
	// by req, freshly built and treated as immutable by the caller, which retains it
	// across synchronizations.
	//
	// changed reports whether it differs from the previous call's: false keeps the
	// stored contribution and ignores res, (nil, true) withdraws it. Withdrawing a
	// process's last contribution takes effect at the next reporting period, since
	// samples already collected keep the attribution they were collected with.
	//
	// A first call, and the one after an exec, arrive with State and the stored
	// contribution already dropped, so an execed process needs no special handling:
	// it looks exactly like one never seen before.
	EnrichResource(req *ResourceRequest) (res *pcommon.Resource, changed bool)
}

// MergeResources combines a base resource with enricher contributions, applied in
// order, so a contribution wins over the base and a later one over an earlier one
// on key collisions. Any input may be nil.
//
// Returns nil if all are nil, and shares a single non-nil input as-is: inputs are
// immutable, so copying is unnecessary.
func MergeResources(base *pcommon.Resource,
	contributions []*pcommon.Resource,
) *pcommon.Resource {
	count, single := 0, base
	if base != nil {
		count = 1
	}
	for _, c := range contributions {
		if c != nil {
			count++
			single = c
		}
	}
	if count <= 1 {
		return single
	}

	merged := pcommon.NewResource()
	attrs := merged.Attributes()
	add := func(r *pcommon.Resource) {
		if r == nil {
			return
		}
		r.Attributes().Range(func(k string, v pcommon.Value) bool {
			v.CopyTo(attrs.PutEmpty(k))
			return true
		})
	}
	add(base)
	for _, c := range contributions {
		add(c)
	}
	return &merged
}
