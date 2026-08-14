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

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
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

	// LiveHeapMaxEntriesPerPID is the maximum number of live allocations
	// tracked per process in the eBPF heap_alloc_live map. Allocations
	// beyond this limit are not tracked for inuse profiling.
	LiveHeapMaxEntriesPerPID int
}

// Probe implements tracer.Probe and processmanager.ProbeAttacher for USDT heap profiling.
type Probe struct {
	cfg     Config
	ctx     context.Context
	manager *usdt.Manager
	tracker *Tracker

	mu        sync.Mutex
	instances map[libpf.PID]*usdt.Instance

	// heapLivePids is the eBPF map that gates per-PID live-heap tracking.
	heapLivePids *cebpf.Map

	// heapAllocLive is the eBPF hash map correlating alloc/free for live-heap.
	heapAllocLive *cebpf.Map

	// heapPIDAllocCount is the eBPF map holding per-PID live alloc counts.
	heapPIDAllocCount *cebpf.Map

	// heapPIDAllocLimit is the eBPF array map holding the per-PID alloc cap.
	heapPIDAllocLimit *cebpf.Map

	// originAlloc and originFree are the dynamically-assigned origin IDs.
	originAlloc uint16
	originFree  uint16

	// livePIDMapFullCount counts PIDs that failed to be added to heap_live_pids.
	livePIDMapFullCount uint64

	done chan struct{}
}

// heapAllocKey mirrors the eBPF HeapAllocKey struct used as the key for
// the heap_alloc_live map.
type heapAllocKey struct {
	PID uint32
	_   uint32 // padding
	Ptr uint64
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
func (hp *Probe) Load(ctx context.Context, reg tracer.ProbeRegistrar, pctx *tracer.ProbeContext) error {
	hp.ctx = ctx

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
		return fmt.Errorf("creating USDT manager: %w", err)
	}

	// Grab map handles for userspace operations.
	if m, ok := pctx.Map("heap_live_pids"); ok {
		hp.heapLivePids = m
	}
	if m, ok := pctx.Map("heap_alloc_live"); ok {
		hp.heapAllocLive = m
	}
	if m, ok := pctx.Map("heap_pid_alloc_count"); ok {
		hp.heapPIDAllocCount = m
	}
	if m, ok := pctx.Map("heap_pid_alloc_limit"); ok {
		hp.heapPIDAllocLimit = m
	}

	// Write the per-PID alloc limit into the eBPF array map so the
	// kernel-side code enforces the cap.
	if hp.heapPIDAllocLimit != nil && hp.cfg.LiveHeapMaxEntriesPerPID > 0 {
		key := uint32(0)
		val := uint32(hp.cfg.LiveHeapMaxEntriesPerPID)
		if err := hp.heapPIDAllocLimit.Put(key, val); err != nil {
			log.Warnf("heap probe: failed to set heap_pid_alloc_limit: %v", err)
		}
	}

	// Create the live heap tracker if live profiling is enabled.
	if hp.cfg.LiveHeapProfiling {
		hp.tracker = NewTracker()
	}

	// Start periodic re-reconciliation goroutine.
	go hp.reconcileLoop(ctx)

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

	// Purge userspace live-heap state and collect pointers for eBPF cleanup.
	var ptrs []uint64
	if hp.tracker != nil {
		ptrs = hp.tracker.HandleProcessExit(pid)
	}

	// Remove entries from heap_alloc_live for this PID.
	if hp.heapAllocLive != nil && len(ptrs) > 0 {
		for _, ptr := range ptrs {
			key := heapAllocKey{PID: uint32(pid), Ptr: ptr}
			_ = hp.heapAllocLive.Delete(key)
		}
	}

	// Remove per-PID alloc count.
	if hp.heapPIDAllocCount != nil {
		pidKey := uint32(pid)
		_ = hp.heapPIDAllocCount.Delete(pidKey)
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
func (hp *Probe) PreHandleTrace(trace *libpf.EbpfTrace) bool {
	if trace.Origin == hp.originFree {
		if hp.tracker != nil {
			hp.tracker.HandleFree(trace.PID, trace.Ptr)
		}
		return false // consumed
	}
	return true
}

// PostHandleTrace implements tracer.PostTraceHandler. It feeds heap alloc
// events to the live heap tracker after symbolization.
func (hp *Probe) PostHandleTrace(trace *libpf.EbpfTrace, hash libpf.TraceHash, frames libpf.Frames) {
	if trace.Origin != hp.originAlloc {
		return
	}
	if hp.tracker == nil {
		return
	}
	hp.tracker.HandleAlloc(
		trace.PID,
		trace.Ptr,
		hash,
		trace.Value,
		frames,
	)
}

// ProduceSamples implements tracer.SampleSource. Returns inuse profiles
// from the live heap tracker snapshot.
func (hp *Probe) ProduceSamples() []samples.SourceProfile {
	if hp.tracker == nil {
		return nil
	}
	entries := hp.tracker.Snapshot()
	if len(entries) == 0 {
		return nil
	}

	result := make([]samples.SourceSample, len(entries))
	for i, e := range entries {
		result[i] = samples.SourceSample{
			PID:       e.PID,
			TraceHash: e.TraceHash,
			Frames:    e.Frames,
			Values:    []int64{e.Space, e.Objects},
		}
	}

	return []samples.SourceProfile{{
		SampleTypes: []samples.SourceSampleType{
			{Type: "inuse_space", Unit: "bytes"},
			{Type: "inuse_objects", Unit: "count"},
		},
		Samples: result,
	}}
}

// GetAndResetMetrics implements tracer.MetricsProvider.
func (hp *Probe) GetAndResetMetrics() []metrics.Metric {
	var result []metrics.Metric
	if hp.tracker != nil {
		result = hp.tracker.GetAndResetMetrics()
	}

	// Append probe-level metrics.
	if hp.livePIDMapFullCount > 0 {
		result = append(result, metrics.Metric{
			ID:    metrics.IDHeapLivePIDMapFull,
			Value: metrics.MetricValue(hp.livePIDMapFullCount),
		})
		hp.livePIDMapFullCount = 0
	}
	return result
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

// setHeapLivePID adds or removes a PID from the heap_live_pids eBPF map
// and notifies the userspace live heap tracker.
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

	// Notify the userspace tracker so it accepts/rejects alloc samples for this PID.
	if hp.tracker != nil {
		log.Debugf("heap probe: SetPIDLiveHeapSupport PID %d enabled=%v", pid, enabled)
		hp.tracker.SetPIDLiveHeapSupport(pid, enabled)
	}
}
