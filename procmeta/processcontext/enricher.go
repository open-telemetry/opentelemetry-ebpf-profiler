// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/procmeta/processcontext"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
)

// enricher reads the OTel process context a process shares through its OTEL_CTX
// memory region. Stateless: the timestamp last published for a process lives in
// that process's state slot.
type enricher struct{}

// NewEnricher returns a ResourceEnricher contributing the resource attributes a
// process publishes in its OTEL_CTX memory region.
func NewEnricher() procmeta.ResourceEnricher {
	return enricher{}
}

func (enricher) ResourceConfig() procmeta.ResourceConfig {
	return procmeta.ResourceConfig{
		WantMapping: func(m *process.RawMapping) bool {
			return IsContextMapping(m.IsExecutable(), m.Path)
		},
	}
}

// state is an enricher's per-process state.
type state struct {
	// publishedAtNs is the timestamp last published, used to skip re-reading an
	// unchanged payload.
	publishedAtNs uint64
}

func (enricher) EnrichResource(req *procmeta.ResourceRequest) (*pcommon.Resource, bool) {
	// The mapping is absent until the process publishes it, possibly well after
	// startup; the eBPF hook on prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME) then triggers
	// a resynchronization, bringing us back here.
	var mappingAddr uint64
	if len(req.Mappings) > 0 {
		mappingAddr = req.Mappings[0].Vaddr
	}

	var oldPublishedAtNs uint64
	if s, ok := (*req.State).(*state); ok {
		oldPublishedAtNs = s.publishedAtNs
	}

	info, publish := Resolve(mappingAddr, req.Process.PID(), req.Process.GetRemoteMemory(),
		oldPublishedAtNs)
	if !publish {
		return nil, false
	}

	*req.State = &state{publishedAtNs: info.PublishedAtNs}
	return info.Resource, true
}
