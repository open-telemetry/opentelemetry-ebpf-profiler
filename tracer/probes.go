// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// ProbeContext bundles the tracer's shared state and provides helpers for building eBPF
// collections inside Probe.Load() implementations.
type ProbeContext struct {
	maps             map[string]*cebpf.Map
	sysVars          SysConfigVars
	links            []link.Link
	registerAttacher func(pm.ProbeAttacher)
	trampolineRef    *CollectTrampolineRef
}

// TrampolineCtxMap returns the per-CPU context map owned by the tracer.
// Probes pass it as a MapReplacement when loading their eBPF collection.
// Do not close it; the tracer closes it on shutdown.
func (c *ProbeContext) TrampolineCtxMap() *cebpf.Map { return c.trampolineRef.CtxMap }

// TrampolineProgID returns the kernel program ID of the collect trampoline.
// Probes use it to populate their tail-call prog array.
func (c *ProbeContext) TrampolineProgID() uint32 { return c.trampolineRef.TailCallDestinationID }

// CollectionSpecWith returns a filtered CollectionSpec built from the tracer's embedded
// eBPF ELF containing only the requested maps, programs, and variables plus ".rodata.var".
// It is a pure filter: system variables are not included or applied.
// Callers that need system variables (e.g. programs that walk the stack) should follow
// this call with applySystemVarsToSpec.
func (c *ProbeContext) CollectionSpecWith(
	extraMaps []string,
	extraProgs []string,
	extraVars []string,
) (*cebpf.CollectionSpec, error) {
	full, err := support.LoadCollectionSpec()
	if err != nil {
		return nil, fmt.Errorf("loading collection spec: %w", err)
	}

	filtered := &cebpf.CollectionSpec{
		Maps:      make(map[string]*cebpf.MapSpec),
		Programs:  make(map[string]*cebpf.ProgramSpec),
		Variables: make(map[string]*cebpf.VariableSpec),
	}

	// .rodata.var holds all RODATA variables; always include it.
	if m, ok := full.Maps[".rodata.var"]; ok {
		filtered.Maps[".rodata.var"] = m.Copy()
	}

	for _, name := range extraMaps {
		m, ok := full.Maps[name]
		if !ok {
			return nil, fmt.Errorf("map %q not found in collection spec", name)
		}
		filtered.Maps[name] = m.Copy()
	}

	for _, name := range extraProgs {
		p, ok := full.Programs[name]
		if !ok {
			return nil, fmt.Errorf("program %q not found in collection spec", name)
		}
		filtered.Programs[name] = p.Copy()
	}

	for _, name := range extraVars {
		v, ok := full.Variables[name]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in collection spec", name)
		}
		filtered.Variables[name] = v
	}

	return filtered, nil
}

// applySystemVarsToSpec loads the mandatory system variables (tpbase_offset,
// task_stack_offset, etc.) from the tracer ELF into coll and writes their
// runtime values. Call this after CollectionSpecWith for programs that perform
// stack unwinding (i.e. the collect trampoline).
func (c *ProbeContext) applySystemVarsToSpec(coll *cebpf.CollectionSpec) error {
	full, err := support.LoadCollectionSpec()
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}
	sv := c.sysVars
	for name, val := range map[string]any{
		"inverse_pac_mask":         sv.inverse_pac_mask,
		"tpbase_offset":            sv.tpbase_offset,
		"task_stack_offset":        sv.task_stack_offset,
		"stack_ptregs_offset":      sv.stack_ptregs_offset,
		"vma_lookup_enabled":       sv.vma_lookup_enabled,
		"vma_vm_file_offset":       sv.vma_vm_file_offset,
		"vma_vm_flags_offset":      sv.vma_vm_flags_offset,
		"task_group_leader_offset": sv.task_group_leader_offset,
		"task_start_time_offset":   sv.task_start_time_offset,
	} {
		v, ok := full.Variables[name]
		if !ok {
			return fmt.Errorf("mandatory system variable %q not found in collection spec", name)
		}
		coll.Variables[name] = v
		if err := v.Set(val); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	if !sv.vma_lookup_enabled {
		disableVMAHelperCalls(coll)
	}
	return nil
}

// RewriteMaps rewrites program map references in coll. The tracer's shared maps are
// merged with probeMaps; probe map names must not shadow tracer-owned map names.
// Only maps actually referenced by the probe's programs are rewritten; tracer-internal
// maps that the probe does not use are silently skipped.
func (c *ProbeContext) RewriteMaps(coll *cebpf.CollectionSpec, probeMaps map[string]*cebpf.Map) error {
	// Build pool: shared tracer maps plus probe-specific maps.
	// .rodata.var is excluded: each probe creates its own isolated RODATA map
	// in LoadProbeUnwinders so that probe-specific variables (e.g. origin_id_probe)
	// are not clobbered by the main tracer's copy.
	pool := make(map[string]*cebpf.Map, len(c.maps)+len(probeMaps))
	for k, v := range c.maps {
		if k == ".rodata.var" {
			continue
		}
		pool[k] = v
	}
	for k, v := range probeMaps {
		if _, exists := pool[k]; exists {
			return fmt.Errorf("probe map %q conflicts with a tracer-owned map", k)
		}
		pool[k] = v
	}

	// Filter pool to only maps referenced by at least one probe program.
	// Scanning instruction references directly avoids calling AssociateMap before
	// rewriteMaps does its own pass, which would corrupt the reference metadata.
	toRewrite := make(map[string]*cebpf.Map, len(pool))
	for name, m := range pool {
	outer:
		for _, progSpec := range coll.Programs {
			for _, ins := range progSpec.Instructions {
				if ins.Reference() == name {
					toRewrite[name] = m
					break outer
				}
			}
		}
	}

	return rewriteMaps(coll, toRewrite)
}

// collReferencesMap reports whether any program in coll references the named map.
func collReferencesMap(coll *cebpf.CollectionSpec, name string) bool {
	for _, progSpec := range coll.Programs {
		for _, ins := range progSpec.Instructions {
			if ins.Reference() == name {
				return true
			}
		}
	}
	return false
}

// LoadProbeUnwinders loads the eBPF programs described by progs into the kernel,
// wiring them into the tracer's kprobe tail-call map and the perf unwinder chain.
// It syncs all VariableSpec values into the .rodata.var MapSpec, creates that map,
// and closes it once the programs are loaded — the kernel holds its own reference
// at that point.
func (c *ProbeContext) LoadProbeUnwinders(
	coll *cebpf.CollectionSpec,
	ebpfProgs map[string]*cebpf.Program,
	progs []ProgLoaderHelper,
	bpfVerifierLogLevel uint32,
) error {
	if err := syncVariablesToMapSpecs(coll); err != nil {
		return err
	}
	if rodataSpec, ok := coll.Maps[".rodata.var"]; ok && collReferencesMap(coll, ".rodata.var") {
		rodataMap, err := cebpf.NewMap(rodataSpec)
		if err != nil {
			return fmt.Errorf("creating .rodata.var: %w", err)
		}
		defer rodataMap.Close()
		if err := rewriteMaps(coll, map[string]*cebpf.Map{".rodata.var": rodataMap}); err != nil {
			return err
		}
	}
	kprobeProgs := c.maps["kprobe_progs"]
	if kprobeProgs == nil {
		return fmt.Errorf("kprobe_progs map not available; ensure the kprobe unwinder chain was loaded at startup")
	}
	perfProgs := c.maps["perf_progs"]
	if perfProgs == nil {
		return fmt.Errorf("perf_progs map not available")
	}
	perCPURecords := c.maps["per_cpu_records"]
	if perCPURecords == nil {
		return fmt.Errorf("per_cpu_records map not available")
	}
	perCPURecordsKp := c.maps["per_cpu_records_kp"]
	if perCPURecordsKp == nil {
		return fmt.Errorf("per_cpu_records_kp map not available")
	}
	return loadProbeUnwinders(coll, ebpfProgs, kprobeProgs, progs,
		bpfVerifierLogLevel, perfProgs.FD(), perCPURecords.FD(), perCPURecordsKp)
}

// CollectTrampolineRef describes what an external probe's eBPF entry program needs
// in order to trigger stack collection via the provided trampoline.
type CollectTrampolineRef struct {
	// CtxMap is the per-CPU array map (key=int, value=u64, max_entries=1) into
	// which the external entry program writes its payload (slot 0) before tail-calling.
	CtxMap *cebpf.Map

	// TailCallDestinationID is the kernel program ID of the loaded trampoline.
	// Use it to populate a BPF_MAP_TYPE_PROG_ARRAY entry so the external entry program
	// can bpf_tail_call into it.
	TailCallDestinationID uint32

	// prog keeps the trampoline kernel program alive for the lifetime of this ref.
	prog *cebpf.Program
}

// Close releases the trampoline program handle and the context map.
// Called by the tracer on shutdown, after all probe links have been detached.
func (r *CollectTrampolineRef) Close() error {
	r.prog.Close()
	return r.CtxMap.Close()
}

// RegisterCollectTrampoline prepares and loads the eBPF programs and maps
// needed for external probes trigger stack trace collection.
func (c *ProbeContext) registerCollectTrampoline(reg ProbeRegistrar, meta *samples.TypeMetadata) (*CollectTrampolineRef, error) {
	const (
		trampolineProgName = "kprobe__external"
		ctxMapName         = "ext_probe_value"
		originVarName      = "origin_id_probe"
	)

	originID, err := reg.Register(meta)
	if err != nil {
		return nil, fmt.Errorf("registering collect trampoline origin: %w", err)
	}

	coll, err := c.CollectionSpecWith(
		[]string{ctxMapName},
		[]string{trampolineProgName},
		[]string{originVarName},
	)
	if err != nil {
		return nil, err
	}
	if err := c.applySystemVarsToSpec(coll); err != nil {
		return nil, err
	}

	v, ok := coll.Variables[originVarName]
	if !ok {
		return nil, fmt.Errorf("variable %q missing after CollectionSpecWith", originVarName)
	}
	if err := v.Set(originID); err != nil {
		return nil, fmt.Errorf("set %s: %w", originVarName, err)
	}

	mapSpec, ok := coll.Maps[ctxMapName]
	if !ok {
		return nil, fmt.Errorf("map %q missing after CollectionSpecWith", ctxMapName)
	}
	ctxMap, err := cebpf.NewMap(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("creating %s: %w", ctxMapName, err)
	}

	// Build a combined map pool: start with tracer-owned maps, then override
	// ext_probe_value with this probe's dedicated per-probe instance.
	// kprobe__external references both tracer-shared maps (kprobe_progs, etc.)
	// and ext_probe_value; both must be rewritten before the program can load.
	pool := make(map[string]*cebpf.Map, len(c.maps)+1)
	for k, v := range c.maps {
		if k == ".rodata.var" {
			continue
		}
		pool[k] = v
	}
	pool[ctxMapName] = ctxMap

	toRewrite := make(map[string]*cebpf.Map, len(pool))
	for name, m := range pool {
	rewriteOuter:
		for _, progSpec := range coll.Programs {
			for _, ins := range progSpec.Instructions {
				if ins.Reference() == name {
					toRewrite[name] = m
					break rewriteOuter
				}
			}
		}
	}
	if err := rewriteMaps(coll, toRewrite); err != nil {
		ctxMap.Close()
		return nil, err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := c.LoadProbeUnwinders(coll, ebpfProgs, []ProgLoaderHelper{
		{
			Name:             trampolineProgName,
			NoTailCallTarget: true,
			Enable:           true,
		},
	}, 0); err != nil {
		ctxMap.Close()
		return nil, err
	}

	prog, ok := ebpfProgs[trampolineProgName]
	if !ok {
		ctxMap.Close()
		return nil, fmt.Errorf("program %q not found after loading", trampolineProgName)
	}

	info, err := prog.Info()
	if err != nil {
		ctxMap.Close()
		return nil, fmt.Errorf("querying trampoline program info: %w", err)
	}
	progID, ok := info.ID()
	if !ok {
		ctxMap.Close()
		return nil, fmt.Errorf("trampoline program ID not available")
	}

	return &CollectTrampolineRef{
		CtxMap:                ctxMap,
		TailCallDestinationID: uint32(progID),
		prog:                  prog,
	}, nil
}

// AddLink registers a global link to be stored and closed by the tracer on shutdown.
// Use this for system-wide hooks, like kprobes, perf events and tracepoints.
func (c *ProbeContext) AddLink(lnk link.Link) {
	c.links = append(c.links, lnk)
}

// AddAttacher registers a per-process attacher with the process manager.
// ProcessManager calls Match/Attach as new mappings appear and Detach on process exit.
func (c *ProbeContext) AddAttacher(a pm.ProbeAttacher) {
	c.registerAttacher(a)
}

// ProbeRegistrar allocates origin IDs backed by sample-type metadata.
// Used internally by the tracer; probe implementations do not call it directly.
type ProbeRegistrar interface {
	Register(meta *samples.TypeMetadata) (uint16, error)
}

// Probe defines the interface that allows custom stack unwinding trigger points.
type Probe interface {
	SampleType() *samples.TypeMetadata
	// Load registers the probe's kernel attachment via probeCtx: call AddLink
	// for a system-wide hook, or AddAttacher for per-process PID-filtered attachment.
	Load(ctx context.Context, probeCtx *ProbeContext) error
}

// PreTraceHandler is an optional interface that Probe implementations may
// satisfy to intercept traces before symbolization. This allows probes to
// consume traces entirely (e.g. heap free events that need only update a
// tracker and should never be symbolized or reported).
//
// The tracer checks whether a Probe satisfies PreTraceHandler after Enable
// and registers it for the origins returned by PreOrigins(). The handler is
// only invoked for traces whose origin matches one of the registered values.
type PreTraceHandler interface {
	// PreOrigins returns the set of origin IDs this handler wants to receive.
	// The tracer dispatches only traces with a matching origin to this handler.
	PreOrigins() []uint16

	// PreHandleTrace is called for each incoming trace (with matching origin)
	// before symbolization.
	//
	// Return true to continue with normal symbolization and reporting, or
	// false to consume the trace (it will not be symbolized or reported).
	PreHandleTrace(trace *libpf.EbpfTrace) bool
}

// PostTraceHandler is an optional interface that Probe implementations may
// satisfy to receive traces after symbolization and reporting. This allows
// probes to perform post-processing on the symbolized trace (e.g. feeding
// alloc events into a live-heap correlator).
//
// The tracer checks whether a Probe satisfies PostTraceHandler after Enable
// and registers it for the origins returned by PostOrigins(). The handler is
// only invoked for traces whose origin matches one of the registered values.
type PostTraceHandler interface {
	// PostOrigins returns the set of origin IDs this handler wants to receive.
	// The tracer dispatches only traces with a matching origin to this handler.
	PostOrigins() []uint16

	// PostHandleTrace is called after symbolization and reporting for traces
	// with a matching origin. Handlers that need the trace hash should call
	// trace.Hash(), which memoizes the result across callers.
	PostHandleTrace(trace *libpf.Trace)
}

// Enable builds a ProbeContext from the tracer's current state and calls p.Load.
// Links registered via AddLink are stored and closed on tracer shutdown. Attachers
// registered via AddAttacher receive per-process lifecycle callbacks from the
// ProcessManager.
//
// If the probe satisfies PreTraceHandler and/or PostTraceHandler, it is
// registered to intercept traces before symbolization or receive them after
// symbolization, respectively.
//
// Enable requires that the kprobe tail-call unwinder chain was loaded at tracer
// startup, which happens when off-CPU profiling is enabled (OffCPUThreshold > 0).
// Without the chain the probe attaches successfully but its tail calls into
// kprobe_progs silently miss, producing no stack samples.
//
// Origin IDs registered inside p.Load are permanently consumed even if Load
// subsequently fails; they cannot be reclaimed.
// Enable returns an error if the tracer has already been closed.
func (t *Tracer) Enable(ctx context.Context, p Probe) error {
	probeCtx := &ProbeContext{
		maps:    t.ebpfMaps,
		sysVars: t.sysConfigVars,
		registerAttacher: func(a pm.ProbeAttacher) {
			t.processManager.RegisterProbeAttacher(a)
		},
	}

	ref, err := probeCtx.registerCollectTrampoline(t.origins, p.SampleType())
	if err != nil {
		return err
	}
	probeCtx.trampolineRef = ref

	if err := p.Load(ctx, probeCtx); err != nil {
		for _, lnk := range probeCtx.links {
			lnk.Close()
		}
		ref.Close()
		return fmt.Errorf("failed to load probe: %w", err)
	}

	if len(probeCtx.links) > 0 {
		h := t.hooks.WLock()
		if h.closed {
			t.hooks.WUnlock(&h)
			for _, lnk := range probeCtx.links {
				lnk.Close()
			}
			ref.Close()
			return fmt.Errorf("tracer is already closed")
		}
		for i, lnk := range probeCtx.links {
			key := hookPoint{group: "probe", name: fmt.Sprintf("%p/%d", p, i)}
			entry := hookEntry{link: lnk}
			if i == 0 {
				entry.closer = ref
			}
			h.m[key] = entry
		}
		t.hooks.WUnlock(&h)
	} else {
		// No links registered; close the ctx map now since nothing will hold it.
		ref.Close()
	}

	if pth, ok := p.(PreTraceHandler); ok {
		for _, origin := range pth.PreOrigins() {
			t.preTraceHandlers[origin] = append(t.preTraceHandlers[origin], pth)
		}
	}

	if pth, ok := p.(PostTraceHandler); ok {
		for _, origin := range pth.PostOrigins() {
			t.postTraceHandlers[origin] = append(t.postTraceHandlers[origin], pth)
		}
	}

	return nil
}
