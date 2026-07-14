// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package heap implements a probe that discovers and attaches USDT heap
// profiling probes (alloc/free) on a per-process basis.
package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"
	"fmt"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const (
	// reconcileInterval is how often we re-check tracked PIDs that have
	// no USDT attachments yet (e.g. libraries loaded after initial sync).
	reconcileInterval = 30 * time.Second

	// reconcileBatchSize limits PIDs re-reconciled per tick.
	reconcileBatchSize = 20
)

// Config holds configuration for the heap probe.
type Config struct {
	// LiveHeapProfiling additionally loads the free probe so that
	// deallocations can be tracked for live/inuse heap reporting.
	LiveHeapProfiling bool
}

// Probe implements tracer.Probe and processmanager.ProbeAttacher for USDT heap profiling.
type Probe struct {
	cfg     Config
	ctx     context.Context
	manager *usdt.Manager

	mu        sync.Mutex
	instances map[libpf.PID]*usdt.Instance

	// heapLivePids is the eBPF map that gates per-PID live-heap tracking.
	heapLivePids *cebpf.Map

	// originAlloc and originFree are the dynamically-assigned origin IDs.
	originAlloc uint16
	originFree  uint16

	// livePIDMapFullCount counts PIDs that failed to be added to heap_live_pids.
	livePIDMapFullCount uint64

	done chan struct{}
}

// New creates a heap probe with the given configuration.
func New(cfg Config) *Probe {
	return &Probe{
		cfg:       cfg,
		instances: make(map[libpf.PID]*usdt.Instance),
		done:      make(chan struct{}),
	}
}

// Load implements tracer.Probe. It loads the heap eBPF programs and creates
// the USDT manager for per-PID attachment.
func (hp *Probe) Load(ctx context.Context, reg tracer.ProbeRegistrar, pctx *tracer.ProbeContext) (link.Link, error) {
	hp.ctx = ctx

	// Register origin IDs. The eBPF programs read these from RODATA.
	var err error
	hp.originAlloc, err = reg.Register(&samples.TypeMetadata{
		SampleType:   "alloc_space",
		SampleUnit:   "bytes",
		ReportValues: true,
	})
	if err != nil {
		return nil, fmt.Errorf("registering heap alloc origin: %w", err)
	}
	hp.originFree, err = reg.Register(&samples.TypeMetadata{
		SampleType: "heap_free",
		SampleUnit: "count",
	})
	if err != nil {
		return nil, fmt.Errorf("registering heap free origin: %w", err)
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
		return nil, fmt.Errorf("building collection spec: %w", err)
	}

	// Set origin IDs in RODATA so the eBPF programs emit the correct values.
	if v, ok := coll.Variables["origin_id_heap_alloc"]; ok {
		if err := v.Set(hp.originAlloc); err != nil {
			return nil, fmt.Errorf("setting origin_id_heap_alloc: %w", err)
		}
	}
	if v, ok := coll.Variables["origin_id_heap_free"]; ok {
		if err := v.Set(hp.originFree); err != nil {
			return nil, fmt.Errorf("setting origin_id_heap_free: %w", err)
		}
	}

	if err := pctx.RewriteMaps(coll, nil); err != nil {
		return nil, fmt.Errorf("rewriting maps: %w", err)
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
		return nil, fmt.Errorf("loading heap eBPF programs: %w", err)
	}

	// Build USDT manager from loaded programs.
	usdtProgs := map[usdt.ProbeKind]*cebpf.Program{}
	if p, ok := ebpfProgs["uprobe_heap_alloc"]; ok {
		usdtProgs[usdt.ProbeHeapAlloc] = p
	}
	if p, ok := ebpfProgs["uprobe_heap_free"]; ok {
		usdtProgs[usdt.ProbeHeapFree] = p
	}
	hp.manager, err = usdt.NewManager(usdtProgs)
	if err != nil {
		return nil, fmt.Errorf("creating USDT manager: %w", err)
	}

	// Grab map handle for userspace operations.
	if m, ok := pctx.Map("heap_live_pids"); ok {
		hp.heapLivePids = m
	}

	// Start periodic re-reconciliation goroutine.
	go hp.reconcileLoop(ctx)

	// Register for per-process callbacks via ProbeAttacher.
	pctx.RegisterProbeAttacher(h)
	return nil, nil
}

// Match implements processmanager.ProbeAttacher. The heap probe matches all
// executable mappings because USDT notes can be in any ELF binary.
func (hp *Probe) Match(_ process.Process, _ *process.RawMapping) bool {
	return true
}

// Attach implements processmanager.ProbeAttacher.
func (hp *Probe) Attach(pr process.Process) error {
	pid := pr.PID()
	hp.mu.Lock()
	inst := hp.instances[pid]
	if inst == nil {
		inst = usdt.NewInstance(pid)
		hp.instances[pid] = inst
	}
	hp.mu.Unlock()

	if _, err := hp.manager.Reconcile(pid, pr, inst); err != nil {
		log.Warnf("heap probe: USDT reconcile for PID %d: %v", pid, err)
	}

	// Update heap_live_pids if the free probe attached (enables live tracking).
	if hp.heapLivePids != nil && hp.cfg.LiveHeapProfiling {
		hasLive := inst.HasProbeKind(usdt.ProbeHeapFree)
		hp.setHeapLivePID(pid, hasLive)
	}
	return nil
}

// Detach implements processmanager.ProbeAttacher.
func (hp *Probe) Detach(pid libpf.PID) {
	hp.mu.Lock()
	inst := hp.instances[pid]
	delete(hp.instances, pid)
	hp.mu.Unlock()

	if inst != nil {
		if err := inst.Detach(); err != nil {
			log.Errorf("heap probe: USDT detach for PID %d: %v", pid, err)
		}
	}

	// Remove from heap_live_pids.
	if hp.heapLivePids != nil {
		hp.setHeapLivePID(pid, false)
	}
}

// close stops the reconcile goroutine and detaches all. Called from
// reconcileLoop's defer when the context is cancelled.
func (hp *Probe) close() {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	for pid, inst := range hp.instances {
		if err := inst.Detach(); err != nil {
			log.Errorf("heap probe: close detach PID %d: %v", pid, err)
		}
		delete(hp.instances, pid)
	}
	if hp.manager != nil {
		hp.manager.Close()
	}
}

// PreHandleTrace implements tracer.PreTraceHandler. It consumes heap free
// events (which need no symbolization or reporting) and lets everything else
// through.
func (h *Probe) PreHandleTrace(trace *libpf.EbpfTrace) bool {
	if trace.Origin == h.originFree {
		return false // consumed
	}
	return true
}

// reconcileLoop periodically re-scans PIDs that have no attachments yet.
func (hp *Probe) reconcileLoop(ctx context.Context) {
	defer close(hp.done)
	defer hp.close()
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hp.reconcileBatch()
		}
	}
}

// reconcileBatch re-reconciles a batch of PIDs that have no USDT attachments.
func (hp *Probe) reconcileBatch() {
	hp.mu.Lock()
	var candidates []libpf.PID
	for pid, inst := range hp.instances {
		if inst.NumAttached() == 0 {
			candidates = append(candidates, pid)
			if len(candidates) >= reconcileBatchSize {
				break
			}
		}
	}
	hp.mu.Unlock()

	for _, pid := range candidates {
		pr := process.New(pid, 0)
		hp.mu.Lock()
		inst := hp.instances[pid]
		hp.mu.Unlock()
		if inst == nil {
			continue
		}
		if _, err := hp.manager.Reconcile(pid, pr, inst); err != nil {
			log.Debugf("heap probe: reconcile PID %d: %v", pid, err)
		}
	}
}

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
