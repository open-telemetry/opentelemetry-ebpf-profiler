// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package usdt provides per-process discovery and attachment of USDT
// (User Statically-Defined Tracepoint) probes for memory profiling.
//
// Probes are discovered by scanning the `.note.stapsdt` sections of the
// executable mappings of each tracked process, filtered to the memory
// profiling provider (see ProbeProvider).
//
// Attachment is PID-scoped via cilium/ebpf's UprobeOptions.PID, and is
// reconciled on every ProcessManager.SynchronizeProcess call so that
// libraries dlopen'd after process start are eventually picked up.
package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// ProbeKind identifies a specific (provider, name) USDT probe we know how
// to handle. The set is intentionally small and fixed: each kind maps to a
// dedicated BPF program with a known argument shape.
type ProbeKind uint8

const (
	ProbeUnknown ProbeKind = iota

	// ProbeHeapAlloc corresponds to the `<provider>:alloc(void *user,
	// uint64_t size, uint64_t weight)` USDT. Fired on sampled allocations.
	ProbeHeapAlloc

	// ProbeHeapFree corresponds to the `<provider>:free(void *ptr)` USDT.
	// Fired when a previously-sampled allocation is freed.
	ProbeHeapFree

	// TODO: ProbeHeapMmap, ProbeHeapMunmap once the sampler library adds them.
)

// ProbeProvider is the USDT provider string we filter `.note.stapsdt`
// entries against. The current value reflects the initial implementation
// in libdd-heap-sampler.
//
// TODO - rename once we've agreed on the OTel name. We own libdd-heap-sampler,
// so both sides can be updated together once an OTel-standard memory-profiling
// provider name is defined.
const ProbeProvider = "ddheap"

// ProbeKey uniquely identifies one PID-scoped attachment. Used for
// deduplication across reconciles and as the storage key on Instance.
type ProbeKey struct {
	PID    libpf.PID
	FileID util.OnDiskFileIdentifier
	Kind   ProbeKind
	// Offset is the probe site file offset, included so that multiple probe
	// sites with the same Kind within one file (rare but legal) do not collide.
	Offset uint64
}

// AttachedProbe is one live attachment.
type AttachedProbe struct {
	Key  ProbeKey
	Link link.Link
}

// parsedProbe is the subset of a parsed `.note.stapsdt` entry we keep, plus
// our Kind tag. Populated by discovery.scanMapping.
type parsedProbe struct {
	Kind            ProbeKind
	Location        uint64 // file offset of probe site
	SemaphoreOffset uint64 // file offset of semaphore, 0 if none
	// TODO: USDT argument descriptors once we move beyond hardcoded SysV ABI.
}
