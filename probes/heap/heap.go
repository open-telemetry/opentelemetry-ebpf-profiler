// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package heap implements a probe that discovers and attaches USDT heap
// profiling probes (alloc/free) on a per-process basis.
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
	"go.opentelemetry.io/ebpf-profiler/util"
)

const heapProbeProvider = "otel_memory"

// Config holds configuration for the heap probe.
type Config struct {
	// LiveHeapProfiling additionally loads the free probe so that
	// deallocations can be tracked for live/inuse heap reporting.
	LiveHeapProfiling bool `mapstructure:"live_heap_profiling"`
}

type attachmentKey struct {
	fileID util.OnDiskFileIdentifier
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

	// heapLivePids is the eBPF map that gates per-PID live-heap tracking.
	heapLivePids *cebpf.Map

	// originAlloc and originFree are the dynamically-assigned origin IDs.
	originAlloc uint16
	originFree  uint16

	// livePIDMapFullCount counts PIDs that failed to be added to heap_live_pids.
	livePIDMapFullCount uint64
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

	// Register origin IDs. The eBPF programs read these from RODATA.
	var err error
	hp.originAlloc, err = reg.Register(&samples.TypeMetadata{
		SampleType:   "alloc_space",
		SampleUnit:   "bytes",
		ReportValues: true,
	})
	if err != nil {
		return fmt.Errorf("registering heap alloc origin: %w", err)
	}
	hp.originFree, err = reg.Register(&samples.TypeMetadata{
		SampleType: "heap_free",
		SampleUnit: "count",
	})
	if err != nil {
		return fmt.Errorf("registering heap free origin: %w", err)
	}

	// Determine which programs to load.
	progNames := []string{"uprobe_heap_alloc"}
	if hp.cfg.LiveHeapProfiling {
		progNames = append(progNames, "uprobe_heap_free")
	}

	// Load eBPF programs via ProbeContext.
	coll, err := pctx.CollectionSpecWith(
		[]string{"heap_live_pids", "heap_pid_alloc_count", "heap_pid_alloc_limit", "heap_alloc_live"},
		progNames,
		[]string{"origin_id_heap_alloc", "origin_id_heap_free"},
	)
	if err != nil {
		return fmt.Errorf("building collection spec: %w", err)
	}

	// Set origin IDs in RODATA so the eBPF programs emit the correct values.
	if v, ok := coll.Variables["origin_id_heap_alloc"]; ok {
		if err := v.Set(hp.originAlloc); err != nil {
			return fmt.Errorf("setting origin_id_heap_alloc: %w", err)
		}
	}
	if v, ok := coll.Variables["origin_id_heap_free"]; ok {
		if err := v.Set(hp.originFree); err != nil {
			return fmt.Errorf("setting origin_id_heap_free: %w", err)
		}
	}

	if err := pctx.RewriteMaps(coll, nil); err != nil {
		return fmt.Errorf("rewriting maps: %w", err)
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	progs := make([]tracer.ProgLoaderHelper, 0, len(progNames))
	for _, name := range progNames {
		progs = append(progs, tracer.ProgLoaderHelper{
			Name:             name,
			NoTailCallTarget: true,
			Enable:           true,
		})
	}
	if err := pctx.LoadProbeUnwinders(coll, ebpfProgs, progs, 0); err != nil {
		return fmt.Errorf("loading heap eBPF programs: %w", err)
	}

	hp.programs = make(map[string]*cebpf.Program, len(ebpfProgs))
	if p, ok := ebpfProgs["uprobe_heap_alloc"]; ok {
		hp.programs["alloc"] = p
	}
	if p, ok := ebpfProgs["uprobe_heap_free"]; ok {
		hp.programs["free"] = p
	}
	hp.discoverer, err = usdt.NewDiscoverer()
	if err != nil {
		return fmt.Errorf("creating USDT discoverer: %w", err)
	}

	// Grab map handle for userspace operations.
	if m, ok := pctx.Map("heap_live_pids"); ok {
		hp.heapLivePids = m
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
	fileID := mapping.GetOnDiskFileIdentifier()
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

	attachedFree := false
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
		attachedFree = attachedFree || candidate.point.Name == "free"
	}

	if attachedFree && hp.heapLivePids != nil && hp.cfg.LiveHeapProfiling {
		hp.setHeapLivePID(pid, true)
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

	if hp.heapLivePids != nil {
		hp.setHeapLivePID(pid, false)
	}
}

// Unload implements tracer.Probe. The heap probe has no global kernel links;
// per-PID resources are released via Detach.
func (hp *Probe) Unload() error { return nil }
// setHeapLivePID adds or removes a PID from the heap_live_pids eBPF map.
func (hp *Probe) setHeapLivePID(pid libpf.PID, enabled bool) {
	key := uint32(pid)
	if enabled {
		val := uint8(1)
		if err := hp.heapLivePids.Put(key, val); err != nil {
			hp.livePIDMapFullCount++
			log.Warnf("heap probe: set heap_live_pids for PID %d: %v (map full?)", pid, err)
		}
	} else {
		if err := hp.heapLivePids.Delete(key); err != nil {
			log.Debugf("heap probe: delete heap_live_pids for PID %d: %v", pid, err)
		}
	}
}
