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
}

// CollectionSpecWith returns a filtered CollectionSpec built from the tracer's embedded
// eBPF ELF. The returned spec contains only the maps, programs, and variables requested
// by the probe plus ".rodata.var" and the mandatory system variables (tpbase_offset,
// task_stack_offset, etc.), which are always included and pre-populated from the values
// determined at tracer startup.
//
// After receiving the spec the probe should:
//  1. Set its own RODATA variables (e.g. origin ID, thresholds).
//  2. Create any probe-specific maps from the returned MapSpecs.
//  3. Call RewriteMaps with those probe-owned maps.
//  4. Call LoadProbeUnwinders to load the programs into the kernel.
//     Variable-to-map syncing is handled automatically inside LoadProbeUnwinders.
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

	// Mandatory system variables must be present in the ELF on all supported arches.
	for _, s := range c.sysVarSetters() {
		v, ok := full.Variables[s.name]
		if !ok {
			return nil, fmt.Errorf("mandatory system variable %q not found in collection spec", s.name)
		}
		filtered.Variables[s.name] = v
	}
	for _, name := range extraVars {
		v, ok := full.Variables[name]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in collection spec", name)
		}
		filtered.Variables[name] = v
	}

	if err := c.applySystemVars(filtered); err != nil {
		return nil, err
	}

	return filtered, nil
}

// sysVar pairs an eBPF variable name with its runtime value.
type sysVar struct {
	name string
	val  any
}

// sysVarSetters returns the name/value pairs for all system variables that every
// probe must apply to its CollectionSpec. It is the single source of truth for
// both the include list in CollectionSpecWith and the apply pass in applySystemVars.
func (c *ProbeContext) sysVarSetters() []sysVar {
	sv := c.sysVars
	return []sysVar{
		{"inverse_pac_mask", sv.inverse_pac_mask},
		{"tpbase_offset", sv.tpbase_offset},
		{"task_stack_offset", sv.task_stack_offset},
		{"stack_ptregs_offset", sv.stack_ptregs_offset},
		{"vma_lookup_enabled", sv.vma_lookup_enabled},
		{"vma_vm_file_offset", sv.vma_vm_file_offset},
		{"vma_vm_flags_offset", sv.vma_vm_flags_offset},
		{"task_group_leader_offset", sv.task_group_leader_offset},
		{"task_start_time_offset", sv.task_start_time_offset},
	}
}

// applySystemVars writes the system configuration values determined at tracer startup into
// coll's RODATA variables and patches programs that depend on VMA helper availability.
// All system variables must be present in coll; CollectionSpecWith guarantees this for
// specs built through the normal path.
func (c *ProbeContext) applySystemVars(coll *cebpf.CollectionSpec) error {
	for _, s := range c.sysVarSetters() {
		v, ok := coll.Variables[s.name]
		if !ok {
			return fmt.Errorf("system variable %q missing from collection spec", s.name)
		}
		if err := v.Set(s.val); err != nil {
			return fmt.Errorf("set %s: %w", s.name, err)
		}
	}
	if !c.sysVars.vma_lookup_enabled {
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
	if rodataSpec, ok := coll.Maps[".rodata.var"]; ok {
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

// ProbeRegistrar lets a Probe register one or more origin IDs during Load.
// Each call to Register allocates a unique ID backed by the supplied metadata;
type ProbeRegistrar interface {
	Register(meta *samples.TypeMetadata) (uint16, error)
}

// Probe defines the interface that allows custom stack unwinding trigger points.
type Probe interface {
	// Load configures the probe. It registers one or more origin IDs via reg,
	// then registers its kernel attachment via probeCtx: call AddLink for a
	// system-wide hook, or AddAttacher for per-process PID-filtered attachment.
	Load(ctx context.Context, reg ProbeRegistrar, probeCtx *ProbeContext) error
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
// probes to perform post-processing that requires the symbolized trace hash
// (e.g. feeding alloc events into a live-heap correlator).
//
// The tracer checks whether a Probe satisfies PostTraceHandler after Enable
// and registers it for the origins returned by PostOrigins(). The handler is
// only invoked for traces whose origin matches one of the registered values,
// avoiding unnecessary hash computation on the hot path.
type PostTraceHandler interface {
	// PostOrigins returns the set of origin IDs this handler wants to receive.
	// The tracer dispatches only traces with a matching origin to this handler.
	PostOrigins() []uint16

	// PostHandleTrace is called after symbolization and reporting for traces
	// with a matching origin.
	PostHandleTrace(trace *libpf.Trace, hash libpf.TraceHash)
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

	if err := p.Load(ctx, t.origins, probeCtx); err != nil {
		return fmt.Errorf("failed to load probe: %w", err)
	}

	if len(probeCtx.links) > 0 {
		h := t.hooks.WLock()
		if h.closed {
			t.hooks.WUnlock(&h)
			for _, lnk := range probeCtx.links {
				lnk.Close()
			}
			return fmt.Errorf("tracer is already closed")
		}
		for i, lnk := range probeCtx.links {
			key := hookPoint{group: "probe", name: fmt.Sprintf("%p/%d", p, i)}
			h.m[key] = lnk
		}
		t.hooks.WUnlock(&h)
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
