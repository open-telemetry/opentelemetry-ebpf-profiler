// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// ProbeContext bundles the tracer's shared state and provides helpers for building eBPF
// collections inside Probe.Load() implementations.
type ProbeContext struct {
	maps    map[string]*cebpf.Map
	sysVars SysConfigVars
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
	return loadProbeUnwinders(coll, ebpfProgs, kprobeProgs, progs,
		bpfVerifierLogLevel, perfProgs.FD())
}

// Probe defines the interface that allows custom stack unwinding trigger points.
type Probe interface {
	// Load attaches a probe that triggers stack unwinding.
	// Returns the link that keeps the probe attached; the caller owns its lifetime.
	Load(originID uint16, ctx *ProbeContext) (link.Link, error)

	// ReportMetadata provides the necessary metadata to report
	// the events of the Probe.
	ReportMetadata() *samples.TypeMetadata
}

// Enable registers the probe's type metadata with the origin registry, builds a
// ProbeContext from the tracer's current state, and calls p.Load. The returned
// link is stored and closed when the tracer shuts down.
//
// Enable requires that the kprobe tail-call unwinder chain was loaded at tracer
// startup. Set LoadProbe: true in the Config passed to NewTracer (or enable
// off-CPU profiling or ProbeLinks, which also trigger the chain load).
// Without the chain the probe attaches successfully but its tail calls into
// kprobe_progs silently miss, producing no stack samples.
//
// The origin ID is registered before p.Load is called, so the reporter will always
// know about the probe's type metadata before any sample from it can arrive.
// If p.Load fails, the origin ID is permanently consumed and cannot be reclaimed.
// Enable must not be called concurrently with Close.
func (t *Tracer) Enable(p Probe) error {
	if !t.kprobeChainLoaded {
		return fmt.Errorf("Enable requires the kprobe unwinder chain to be loaded at startup: " +
			"set LoadProbe: true in the tracer Config")
	}

	originID, err := t.origins.register(p.ReportMetadata())
	if err != nil {
		return fmt.Errorf("failed to register probe origin: %w", err)
	}

	ctx := &ProbeContext{
		maps:    t.ebpfMaps,
		sysVars: t.sysConfigVars,
	}

	lnk, err := p.Load(originID, ctx)
	if err != nil {
		return fmt.Errorf("failed to load probe: %w", err)
	}

	if lnk != nil {
		t.hooks[hookPoint{group: "probe", name: fmt.Sprintf("%d", originID)}] = lnk
	}
	return nil
}
