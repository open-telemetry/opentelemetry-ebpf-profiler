// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package heap implements a probe that discovers and attaches USDT heap
// profiling probes on a per-process basis.
package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const (
	heapProbeProvider = "otel_memory"
	allocProgName     = "uprobe_heap_alloc"
	allocOriginVar    = "origin_id_heap_alloc"
)

type attachmentKey struct {
	fileID libpf.FileID
	name   string
	offset uint64
}

type attachment struct {
	lnk       io.Closer
	specKeys  map[support.USDTSpecKey]libpf.Void
	detaching bool
}

// Probe implements tracer.Probe and processmanager.ProbeAttacher for USDT heap profiling.
type Probe struct {
	discoverer *usdt.Discoverer
	programs   map[string]*cebpf.Program
	usdtSpecs  *cebpf.Map

	mu          sync.Mutex
	unloaded    bool
	attachments map[libpf.PID]map[attachmentKey]*attachment

	// originAlloc is the dynamically-assigned origin ID for heap allocations.
	originAlloc uint16
}

// New creates a heap probe.
func New() *Probe {
	return &Probe{
		attachments: make(map[libpf.PID]map[attachmentKey]*attachment),
	}
}

// probeVirtualAddress translates a file offset to its runtime virtual address.
// The boolean reports whether the offset is contained in mapping. An error is
// returned when a contained offset can't be represented as a virtual address.
func probeVirtualAddress(mapping *process.RawMapping, fileOffset uint64) (uint64, bool, error) {
	if fileOffset < mapping.FileOffset {
		return 0, false, nil
	}
	delta := fileOffset - mapping.FileOffset
	if delta >= mapping.Length {
		return 0, false, nil
	}
	if mapping.Vaddr > math.MaxUint64-delta {
		return 0, false, errors.New("probe virtual address overflows")
	}
	return mapping.Vaddr + delta, true, nil
}

// Derive an unbiased object-count estimator from the
// byte-weighted values. Each event carries:
//
//	weighted_bytes = unbiased byte estimate (see ADR 00003)
//	size           = raw allocation size in bytes
//
// Object count = weighted_bytes / size. This is the standard
// convention used by tcmalloc, jemalloc, and Go's pprof.
//
// We compute this in userspace rather than eBPF to keep the
// kernel/userspace interface simple, preserve the raw size
// for potential future use (e.g. allocation-size histograms),
// and avoid the eBPF program needing to transform values.
//
// Fall back to 1 if size is unknown/zero rather than
// dividing by zero.
func allocObjectsValue(weightedBytes int64, rawSize uint64) int64 {
	size := int64(rawSize)
	if size <= 0 {
		return 1
	}
	return max(weightedBytes/size, 1)
}

func appendAllocValues(dst []int64, meta *samples.TraceEventMeta) []int64 {
	var weightedBytes int64
	var size uint64
	if len(meta.ContextValues) > 0 {
		weightedBytes = int64(meta.ContextValues[0])
	}
	if len(meta.ContextValues) > 2 {
		size = meta.ContextValues[2]
	}
	return append(dst, weightedBytes, allocObjectsValue(weightedBytes, size))
}

// Load implements tracer.Probe. It loads the heap eBPF programs and creates
// the USDT discoverer used during per-process attachment.
func (hp *Probe) Load(_ context.Context, reg tracer.ProbeRegistrar, pctx *tracer.ProbeContext) error {
	// Register origin ID. The eBPF program reads this from RODATA.
	var err error
	hp.originAlloc, err = reg.Register(&samples.TypeMetadata{
		SampleTypes: []samples.SampleType{
			{Type: "alloc_space", Unit: "bytes"},
			{Type: "alloc_objects", Unit: "count"},
		},
		ReportValues: true,
		AppendValues: appendAllocValues,
	})
	if err != nil {
		return fmt.Errorf("registering heap alloc origin: %w", err)
	}

	// Load eBPF programs via ProbeContext.
	coll, err := pctx.CollectionSpecWith(
		[]string{"usdt_specs"},
		[]string{allocProgName},
		[]string{allocOriginVar},
	)
	if err != nil {
		return fmt.Errorf("building collection spec: %w", err)
	}
	// Probe-owned maps bypass the tracer's normal map-size adaptation.
	coll.Maps["usdt_specs"].MaxEntries <<= uint32(pctx.MapScaleFactor())

	// Set origin ID in RODATA so the eBPF program emits the correct value.
	if v, ok := coll.Variables[allocOriginVar]; ok {
		if err := v.Set(hp.originAlloc); err != nil {
			return fmt.Errorf("setting origin_id_heap_alloc: %w", err)
		}
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("adjusting memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	specMap, err := cebpf.NewMap(coll.Maps["usdt_specs"])
	if err != nil {
		return fmt.Errorf("creating usdt_specs map: %w", err)
	}
	if err := pctx.RewriteMaps(coll, map[string]*cebpf.Map{"usdt_specs": specMap}); err != nil {
		_ = specMap.Close()
		return fmt.Errorf("rewriting maps: %w", err)
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	progs := []tracer.ProgLoaderHelper{{
		Name:             allocProgName,
		NoTailCallTarget: true,
		Enable:           true,
	}}
	if err := pctx.LoadProbeUnwinders(coll, ebpfProgs, progs, 0); err != nil {
		_ = specMap.Close()
		return fmt.Errorf("loading heap eBPF programs: %w", err)
	}

	hp.programs = make(map[string]*cebpf.Program, len(ebpfProgs))
	if p, ok := ebpfProgs[allocProgName]; ok {
		hp.programs["alloc"] = p
	}
	hp.discoverer, err = usdt.NewDiscoverer()
	if err != nil {
		_ = specMap.Close()
		return fmt.Errorf("creating USDT discoverer: %w", err)
	}

	// Register for per-process callbacks via ProbeAttacher.
	hp.usdtSpecs = specMap
	if err := pctx.AddAttacher(hp); err != nil {
		hp.usdtSpecs = nil
		_ = specMap.Close()
		return err
	}
	return nil
}

// Match implements processmanager.ProbeAttacher. The heap probe matches all
// executable mappings because USDT notes can be in any ELF binary.
func (hp *Probe) Match(_ process.Process, _ *process.RawMapping) bool {
	return true
}

// Attach implements processmanager.ProbeAttacher.
func (hp *Probe) Attach(pr process.Process, mapping *process.RawMapping,
	fileID libpf.FileID, elfRef *pfelf.Reference,
) error {
	pid := pr.PID()

	// Discover USDT attachment points in this mapping. The discoverer
	// caches results by backing-file identity so repeated calls for the
	// same binary are cheap.
	points, err := hp.discoverer.Discover(elfRef, fileID)
	if err != nil {
		if len(points) == 0 {
			return fmt.Errorf("discovering USDT probes: %w", err)
		}
		log.Warnf("heap probe: skipped invalid USDT notes for PID %d mapping %s: %v",
			pid, mapping.Path, err)
	}

	// Filter to our provider and probe names, and to sites contained in this
	// mapping. Discovery returns every site in the backing ELF, while runtime
	// addresses are specific to each process mapping.
	type candidate struct {
		key     attachmentKey
		point   usdt.AttachmentPoint
		prog    *cebpf.Program
		specKey support.USDTSpecKey
		spec    support.USDTSpec
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
		// USDT notes identify sites by file offset, while the spec map is keyed by
		// the runtime PC. Ignore sites that belong to another mapping of this ELF.
		virtualAddress, contained, err := probeVirtualAddress(mapping, point.Location)
		if err != nil {
			log.Warnf("heap probe: resolve virtual address for %s:%s PID %d at offset %#x: %v",
				point.Provider, point.Name, pid, point.Location, err)
			continue
		}
		if !contained {
			continue
		}
		spec, err := parseAllocSpec(point)
		if err != nil {
			log.Warnf("heap probe: invalid arguments for %s:%s at offset %#x: %v",
				point.Provider, point.Name, point.Location, err)
			continue
		}
		key := attachmentKey{fileID: fileID, name: point.Name, offset: point.Location}
		// ProcessManager PIDs originate from the translated pid_events path,
		// matching get_pid_tgid_leader() in the firing BPF program.
		specKey := support.USDTSpecKey{
			Pid:     uint32(pid),
			Address: virtualAddress,
		}
		// This pre-check avoids reopening an already registered site in the common
		// case. The locked check in the attachment loop remains authoritative.
		hp.mu.Lock()
		attached := hp.attachments[pid][key]
		registered := false
		if attached != nil {
			_, registered = attached.specKeys[specKey]
		}
		hp.mu.Unlock()
		if !registered {
			candidates = append(candidates, candidate{
				key: key, point: point, prog: prog, specKey: specKey, spec: spec,
			})
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

	// Reserve each site and register its argument layout before attaching the
	// uprobe. Multiple mappings of the same file share one PID-scoped link but
	// each runtime address gets its own specification.
	for _, candidate := range candidates {
		hp.mu.Lock()
		if hp.unloaded {
			hp.mu.Unlock()
			return nil
		}
		attached := hp.attachments[pid][candidate.key]
		if attached != nil {
			if attached.detaching {
				hp.mu.Unlock()
				log.Warnf("heap probe: skip mapping for detaching %s:%s PID %d at address %#x",
					candidate.point.Provider, candidate.point.Name, pid,
					candidate.specKey.Address)
				continue
			}
			if _, exists := attached.specKeys[candidate.specKey]; exists {
				hp.mu.Unlock()
				continue
			}
			if err := hp.usdtSpecs.Put(candidate.specKey, candidate.spec); err != nil {
				hp.mu.Unlock()
				metrics.Add(metrics.IDUSDTSpecsUpdate, 1)
				log.Warnf("heap probe: register arguments for %s:%s PID %d at address %#x: %v",
					candidate.point.Provider, candidate.point.Name, pid,
					candidate.specKey.Address, err)
				continue
			}
			attached.specKeys[candidate.specKey] = libpf.Void{}
			hp.mu.Unlock()
			// A PID-scoped uprobe is registered by inode and file offset, so the
			// existing link fires for every mapping of that site in this process.
			continue
		}
		if err := hp.usdtSpecs.Put(candidate.specKey, candidate.spec); err != nil {
			hp.mu.Unlock()
			metrics.Add(metrics.IDUSDTSpecsUpdate, 1)
			log.Warnf("heap probe: register arguments for %s:%s PID %d at address %#x: %v",
				candidate.point.Provider, candidate.point.Name, pid,
				candidate.specKey.Address, err)
			continue
		}
		if hp.attachments[pid] == nil {
			hp.attachments[pid] = make(map[attachmentKey]*attachment)
		}
		pending := &attachment{specKeys: map[support.USDTSpecKey]libpf.Void{
			candidate.specKey: {},
		}}
		hp.attachments[pid][candidate.key] = pending
		hp.mu.Unlock()

		lnk, err := ex.Uprobe("", candidate.prog, &link.UprobeOptions{
			PID:          int(pid),
			Address:      candidate.point.Location,
			RefCtrOffset: candidate.point.SemaphoreOffset,
		})
		if err != nil {
			hp.mu.Lock()
			if hp.attachments[pid][candidate.key] == pending {
				// A matching reservation means neither Detach nor Unload has removed
				// the attachment state or taken ownership of the spec map.
				delete(hp.attachments[pid], candidate.key)
				if len(hp.attachments[pid]) == 0 {
					delete(hp.attachments, pid)
				}
				for specKey := range pending.specKeys {
					if deleteErr := hp.usdtSpecs.Delete(specKey); deleteErr != nil &&
						!errors.Is(deleteErr, cebpf.ErrKeyNotExist) {
						log.Warnf("heap probe: roll back arguments for PID %d at address %#x: %v",
							pid, specKey.Address, deleteErr)
					}
				}
			}
			hp.mu.Unlock()
			log.Warnf("heap probe: attach %s:%s for PID %d at offset %#x: %v",
				candidate.point.Provider, candidate.point.Name, pid,
				candidate.point.Location, err)
			continue
		}

		hp.mu.Lock()
		if hp.unloaded || pending.detaching || hp.attachments[pid][candidate.key] != pending {
			// Detach or Unload claimed or removed the reservation while the
			// kernel attachment was being created. Its cleanup owns the specs;
			// only the unpublished link remains for this goroutine to close.
			hp.mu.Unlock()
			if closeErr := lnk.Close(); closeErr != nil {
				log.Errorf("heap probe: close unpublished %s:%s link for PID %d: %v",
					candidate.point.Provider, candidate.point.Name, pid, closeErr)
			}
			continue
		}
		pending.lnk = lnk
		hp.mu.Unlock()
	}
	return nil
}

// Detach implements processmanager.ProbeAttacher.
func (hp *Probe) Detach(pid libpf.PID) {
	type cleanup struct {
		key      attachmentKey
		attached *attachment
		lnk      io.Closer
	}

	hp.mu.Lock()
	cleanups := make([]cleanup, 0, len(hp.attachments[pid]))
	for key, attached := range hp.attachments[pid] {
		if attached.detaching {
			continue
		}
		attached.detaching = true
		cleanups = append(cleanups, cleanup{key: key, attached: attached, lnk: attached.lnk})
		// Unload may take ownership of the remaining state while Close runs, so
		// make it clear that this goroutine owns the link from this point.
		attached.lnk = nil
	}
	hp.mu.Unlock()

	for _, cleanup := range cleanups {
		if cleanup.lnk != nil {
			if err := cleanup.lnk.Close(); err != nil {
				log.Errorf("heap probe: detach PID %d probe %s at offset %#x: %v",
					pid, cleanup.key.name, cleanup.key.offset, err)
			}
		}
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()
	for _, cleanup := range cleanups {
		// Pointer identity prevents an old cleanup from deleting a replacement
		// attachment and its specs if the same PID and key are reused.
		if hp.attachments[pid][cleanup.key] != cleanup.attached {
			// Unload or another cleanup already removed this reservation and its specs.
			continue
		}
		if hp.usdtSpecs != nil {
			for specKey := range cleanup.attached.specKeys {
				if err := hp.usdtSpecs.Delete(specKey); err != nil &&
					!errors.Is(err, cebpf.ErrKeyNotExist) {
					log.Errorf("heap probe: delete USDT arguments for PID %d at address %#x: %v",
						pid, specKey.Address, err)
				}
			}
		}
		delete(hp.attachments[pid], cleanup.key)
	}
	if len(hp.attachments[pid]) == 0 {
		delete(hp.attachments, pid)
	}
}

// Unload implements tracer.Probe. Uprobe links are fd-backed, so the runtime
// releases them automatically when the profiler exits; per-PID cleanup also
// happens via Detach. We close any remaining links explicitly here so the
// lifecycle is clear and does not rely on Detach being called for every PID
// during shutdown.
func (hp *Probe) Unload() error {
	hp.mu.Lock()
	if hp.unloaded {
		hp.mu.Unlock()
		return nil
	}
	hp.unloaded = true
	attachments := hp.attachments
	specMap := hp.usdtSpecs
	hp.attachments = make(map[libpf.PID]map[attachmentKey]*attachment)
	hp.usdtSpecs = nil
	hp.mu.Unlock()

	var errs error
	for pid, byKey := range attachments {
		for key, attached := range byKey {
			if attached.lnk != nil {
				if err := attached.lnk.Close(); err != nil {
					log.Errorf("heap probe: unload PID %d probe %s at offset %#x: %v",
						pid, key.name, key.offset, err)
					errs = errors.Join(errs, err)
				}
			}
			if specMap != nil {
				for specKey := range attached.specKeys {
					if err := specMap.Delete(specKey); err != nil &&
						!errors.Is(err, cebpf.ErrKeyNotExist) {
						errs = errors.Join(errs, err)
					}
				}
			}
		}
	}
	if specMap != nil {
		errs = errors.Join(errs, specMap.Close())
	}
	return errs
}
