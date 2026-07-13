// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package heap implements a probe that discovers and attaches USDT heap
// profiling probes on a per-process basis.
package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"
	"fmt"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const (
	heapProbeProvider = "otel_memory"
	allocProgName     = "uprobe_heap_alloc"
	allocOriginVar    = "origin_id_heap_alloc"
)

// Config holds configuration for the heap probe.
type Config struct{}

type attachmentKey struct {
	fileID libpf.FileID
	name   string
	offset uint64
}

// Probe implements tracer.Probe and processmanager.ProbeAttacher for USDT heap profiling.
type Probe struct {
	cfg        Config
	discoverer *usdt.Discoverer
	programs   map[string]*cebpf.Program

	mu          sync.Mutex
	attachments map[libpf.PID]map[attachmentKey]link.Link

	// originAlloc is the dynamically-assigned origin ID for heap allocations.
	originAlloc uint16
}

// New creates a heap probe with the given configuration.
func New(cfg Config) *Probe {
	return &Probe{
		cfg:         cfg,
		attachments: make(map[libpf.PID]map[attachmentKey]link.Link),
	}
}

// Load implements tracer.Probe. It loads the heap eBPF programs and creates
// the USDT discoverer used during per-process attachment.
func (hp *Probe) Load(_ context.Context, reg tracer.ProbeRegistrar, pctx *tracer.ProbeContext) error {
	// Register origin ID. The eBPF program reads this from RODATA.
	var err error
	hp.originAlloc, err = reg.Register(&samples.TypeMetadata{
		SampleType:   "alloc_space",
		SampleUnit:   "bytes",
		ReportValues: true,
	})
	if err != nil {
		return fmt.Errorf("registering heap alloc origin: %w", err)
	}

	// Load eBPF programs via ProbeContext.
	coll, err := pctx.CollectionSpecWith(
		nil,
		[]string{allocProgName},
		[]string{allocOriginVar},
	)
	if err != nil {
		return fmt.Errorf("building collection spec: %w", err)
	}

	// Set origin ID in RODATA so the eBPF program emits the correct value.
	if v, ok := coll.Variables[allocOriginVar]; ok {
		if err := v.Set(hp.originAlloc); err != nil {
			return fmt.Errorf("setting origin_id_heap_alloc: %w", err)
		}
	}

	if err := pctx.RewriteMaps(coll, nil); err != nil {
		return fmt.Errorf("rewriting maps: %w", err)
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	progs := []tracer.ProgLoaderHelper{{
		Name:             allocProgName,
		NoTailCallTarget: true,
		Enable:           true,
	}}
	if err := pctx.LoadProbeUnwinders(coll, ebpfProgs, progs, 0); err != nil {
		return fmt.Errorf("loading heap eBPF programs: %w", err)
	}

	hp.programs = make(map[string]*cebpf.Program, len(ebpfProgs))
	if p, ok := ebpfProgs[allocProgName]; ok {
		hp.programs["alloc"] = p
	}
	hp.discoverer, err = usdt.NewDiscoverer()
	if err != nil {
		return fmt.Errorf("creating USDT discoverer: %w", err)
	}

	// Register for per-process callbacks via ProbeAttacher.
	pctx.AddAttacher(hp)
	return nil
}

// Match implements processmanager.ProbeAttacher. The heap probe matches all
// executable mappings because USDT notes can be in any ELF binary.
func (hp *Probe) Match(_ process.Process, _ *process.RawMapping) bool {
	return true
}

// Attach implements processmanager.ProbeAttacher.
func (hp *Probe) Attach(pr process.Process, mapping *process.RawMapping) error {
	pid := pr.PID()
	fileID, err := pr.CalculateMappingFileID(mapping)
	if err != nil {
		return fmt.Errorf("calculate file ID for %s: %w", mapping.Path, err)
	}

	// Discover USDT attachment points in this mapping. The discoverer
	// caches results by backing-file identity so repeated calls for the
	// same binary are cheap.
	ref := pfelf.NewReferenceWithOpenFunc(mapping.Path, pr, func() (*pfelf.File, error) {
		return process.OpenELFMapping(pr, mapping)
	})
	defer ref.Close()

	points, err := hp.discoverer.Discover(ref, fileID)
	if err != nil {
		if len(points) == 0 {
			return fmt.Errorf("discovering USDT probes: %w", err)
		}
		log.Warnf("heap probe: skipped invalid USDT notes for PID %d mapping %s: %v",
			pid, mapping.Path, err)
	}

	// Filter to our provider and probe names, and skip sites we've
	// already attached. A single mapping may contain multiple USDT
	// sites; SynchronizePIDs may also re-trigger Attach for the same
	// mapping, so dedup by (fileID, name, offset).
	type candidate struct {
		key   attachmentKey
		point usdt.AttachmentPoint
		prog  *cebpf.Program
	}
	candidates := make([]candidate, 0, len(points))
	for _, point := range points {
		if point.Provider != heapProbeProvider {
			continue
		}
		prog, ok := hp.programs[point.Name]
		if !ok {
			continue
		}
		key := attachmentKey{fileID: fileID, name: point.Name, offset: point.Location}
		hp.mu.Lock()
		_, attached := hp.attachments[pid][key]
		hp.mu.Unlock()
		if !attached {
			candidates = append(candidates, candidate{key: key, point: point, prog: prog})
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Open the backing file to get an fd for the uprobe. We go through
	// OpenMappingFile (which uses /proc/<pid>/map_files) for deleted-file
	// and mount-namespace safety.
	mappingFile, err := pr.OpenMappingFile(mapping)
	if err != nil {
		return fmt.Errorf("open mapping %s: %w", mapping.Path, err)
	}
	defer mappingFile.Close()

	fdFile, ok := mappingFile.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("mapping %s has no file descriptor", mapping.Path)
	}
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", fdFile.Fd()))
	if err != nil {
		return fmt.Errorf("open mapping %s as executable: %w", mapping.Path, err)
	}

	// Attach a PID-scoped uprobe for each candidate site.
	for _, candidate := range candidates {
		lnk, err := ex.Uprobe("", candidate.prog, &link.UprobeOptions{
			PID:          int(pid),
			Address:      candidate.point.Location,
			RefCtrOffset: candidate.point.SemaphoreOffset,
		})
		if err != nil {
			log.Warnf("heap probe: attach %s:%s for PID %d at offset %#x: %v",
				candidate.point.Provider, candidate.point.Name, pid,
				candidate.point.Location, err)
			continue
		}

		// Double-check under lock: another goroutine may have attached
		// the same site between our candidate check and now.
		hp.mu.Lock()
		if hp.attachments[pid] == nil {
			hp.attachments[pid] = make(map[attachmentKey]link.Link)
		}
		if _, exists := hp.attachments[pid][candidate.key]; exists {
			hp.mu.Unlock()
			_ = lnk.Close()
			continue
		}
		hp.attachments[pid][candidate.key] = lnk
		hp.mu.Unlock()
	}
	return nil
}

// Detach implements processmanager.ProbeAttacher.
func (hp *Probe) Detach(pid libpf.PID) {
	hp.mu.Lock()
	attachments := hp.attachments[pid]
	delete(hp.attachments, pid)
	hp.mu.Unlock()

	for key, lnk := range attachments {
		if err := lnk.Close(); err != nil {
			log.Errorf("heap probe: detach PID %d probe %s at offset %#x: %v",
				pid, key.name, key.offset, err)
		}
	}
}

// Unload implements tracer.Probe. The heap probe has no global kernel links;
// per-PID resources are released via Detach.
func (hp *Probe) Unload() error { return nil }
