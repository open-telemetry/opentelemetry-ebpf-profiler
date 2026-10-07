// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package offcpu implements an off-CPU profiling probe that records how long
// tasks spend blocked off-CPU between scheduler context switches.
package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"context"
	"errors"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	defaultMapEntries = 4096
	deferredTracesMap = "deferred_traces"
	programsMap       = "probe_off_cpu_progs"
	schedTimesMap     = "probe_off_cpu_sched_times"
	// MaxMapEntries caps pending trace payloads at approximately 1 GiB.
	MaxMapEntries = (1 << 30) / support.Sizeof_TraceWithData

	// ModeTracepoint unwinds when a task switches out and completes the sample
	// from the same sched_switch tracepoint when that task switches back in.
	ModeTracepoint Mode = "tracepoint"
	// ModeTracepointKprobe retains the previous sched_switch plus
	// finish_task_switch kprobe implementation.
	ModeTracepointKprobe Mode = "tracepoint-kprobe"
)

// Mode selects the scheduler hooks used for off-CPU profiling.
type Mode string

// Config holds the YAML configuration for the off-CPU probe.
//
//	extensions:
//	   offcpu:
//	     threshold: 0.1     # capture probability in ]0.0, 1.0]
//	     map_entries: 8192  # optional pending trace capacity; 0 uses 4096
//	     mode: tracepoint    # optional; empty defaults to tracepoint-kprobe
type Config struct {
	Threshold  float64 `mapstructure:"threshold"`
	MapEntries uint    `mapstructure:"map_entries"`
	Mode       Mode    `mapstructure:"mode"`
}

// Validate implements confmap.Validator.
func (cfg *Config) Validate() error {
	if cfg.Threshold <= 0.0 || cfg.Threshold > 1.0 {
		return fmt.Errorf("offcpu: threshold %f is out of range ]0.0, 1.0]", cfg.Threshold)
	}
	if cfg.MapEntries > MaxMapEntries {
		return fmt.Errorf("offcpu: map entries %d exceeds limit (max: %d)",
			cfg.MapEntries, MaxMapEntries)
	}
	if cfg.Mode != "" && cfg.Mode != ModeTracepoint && cfg.Mode != ModeTracepointKprobe {
		return fmt.Errorf("offcpu: unsupported mode %q", cfg.Mode)
	}
	return nil
}

type probe struct {
	threshold  uint32
	mapEntries uint32
	mode       Mode
	links      []link.Link
}

func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType:   "off_cpu",
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	})
	if err != nil {
		return fmt.Errorf("registering off-CPU origin: %w", err)
	}

	switch p.mode {
	case ModeTracepoint:
		return p.loadTracepoint(originID, probeCtx)
	case "", ModeTracepointKprobe:
		return p.loadTracepointKprobe(originID, probeCtx)
	default:
		return fmt.Errorf("unsupported off-CPU mode %q", p.mode)
	}
}

func (p *probe) loadTracepoint(originID uint16, probeCtx *tracer.ProbeContext) error {
	err := p.loadTracepointVariant(originID, probeCtx, true)
	if err == nil {
		return nil
	}

	log.Warnf("BTF sched_switch tracepoint unavailable, falling back to raw tracepoint: %v", err)
	return p.loadTracepointVariant(originID, probeCtx, false)
}

func (p *probe) loadTracepointVariant(originID uint16, probeCtx *tracer.ProbeContext,
	useBTF bool,
) error {
	processFreeProgram := "off_cpu_raw_tracepoint__sched_process_free"
	entryProgram := "raw_tracepoint__sched_switch"
	if useBTF {
		entryProgram = "tp_btf__sched_switch"
	}
	coll, err := probeCtx.CollectionSpecWith(
		[]string{deferredTracesMap, programsMap},
		[]string{entryProgram, processFreeProgram},
		[]string{"off_cpu_threshold", "origin_id_off_cpu", "defer_traces", "deferred_origin_id"},
	)
	if err != nil {
		return err
	}

	if err := coll.Variables["off_cpu_threshold"].Set(p.threshold); err != nil {
		return fmt.Errorf("set off_cpu_threshold: %w", err)
	}
	if err := coll.Variables["origin_id_off_cpu"].Set(originID); err != nil {
		return fmt.Errorf("set origin_id_off_cpu: %w", err)
	}
	if err := coll.Variables["defer_traces"].Set(true); err != nil {
		return fmt.Errorf("set defer_traces: %w", err)
	}
	if err := coll.Variables["deferred_origin_id"].Set(originID); err != nil {
		return fmt.Errorf("set deferred_origin_id: %w", err)
	}

	coll.Maps[deferredTracesMap].MaxEntries = traceMapSize(p.mapEntries)

	traceMap, err := cebpf.NewMap(coll.Maps[deferredTracesMap])
	if err != nil {
		return fmt.Errorf("creating %s map: %w", deferredTracesMap, err)
	}
	defer traceMap.Close()

	tailcallMap, err := cebpf.NewMap(coll.Maps[programsMap])
	if err != nil {
		return fmt.Errorf("creating %s map: %w", programsMap, err)
	}
	defer tailcallMap.Close()

	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{
		deferredTracesMap: traceMap,
		programsMap:       tailcallMap,
	}); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	defer closePrograms(ebpfProgs)
	entry := []tracer.ProgLoaderHelper{
		{Name: entryProgram, NoTailCallTarget: true, Enable: true},
		{Name: processFreeProgram, NoTailCallTarget: true, Enable: true},
	}
	err = probeCtx.LoadProbeUnwinders(coll, ebpfProgs, entry, 0)
	if err != nil {
		return err
	}

	if useBTF {
		if err := p.attachBTFTracepointProgram(ebpfProgs, entryProgram); err != nil {
			return err
		}
	} else if err := p.attachRawTracepointProgram(ebpfProgs, entryProgram, "sched_switch"); err != nil {
		return err
	}
	return p.attachRawTracepointProgram(ebpfProgs, processFreeProgram, "sched_process_free")
}

func (p *probe) loadTracepointKprobe(originID uint16, probeCtx *tracer.ProbeContext) error {
	coll, err := probeCtx.CollectionSpecWith(
		[]string{schedTimesMap},
		[]string{"finish_task_switch", "tracepoint__sched_switch_legacy"},
		[]string{"off_cpu_threshold", "origin_id_off_cpu"},
	)
	if err != nil {
		return err
	}

	if err := coll.Variables["off_cpu_threshold"].Set(p.threshold); err != nil {
		return fmt.Errorf("set off_cpu_threshold: %w", err)
	}
	if err := coll.Variables["origin_id_off_cpu"].Set(originID); err != nil {
		return fmt.Errorf("set origin_id_off_cpu: %w", err)
	}
	coll.Maps[schedTimesMap].MaxEntries = traceMapSize(p.mapEntries)

	schedMap, err := cebpf.NewMap(coll.Maps[schedTimesMap])
	if err != nil {
		return fmt.Errorf("creating %s map: %w", schedTimesMap, err)
	}
	defer schedMap.Close()
	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{schedTimesMap: schedMap}); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{Name: "finish_task_switch", NoTailCallTarget: true, Enable: true},
		{Name: "tracepoint__sched_switch_legacy", NoTailCallTarget: true, Enable: true},
	}, 0); err != nil {
		return err
	}

	return p.attachTracepointKprobePrograms(ebpfProgs, probeCtx)
}

func (p *probe) attachTracepointProgram(ebpfProgs map[string]*cebpf.Program, name string) error {
	tpProg, ok := ebpfProgs[name]
	if !ok {
		return fmt.Errorf("%s program not found after loading", name)
	}

	tpLink, err := link.Tracepoint("sched", "sched_switch", tpProg, nil)
	if err != nil {
		return fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}
	p.links = append(p.links, tpLink)

	return nil
}

func (p *probe) attachRawTracepointProgram(ebpfProgs map[string]*cebpf.Program,
	name, tracepoint string,
) error {
	prog, ok := ebpfProgs[name]
	if !ok {
		return fmt.Errorf("%s program not found after loading", name)
	}

	tpLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    tracepoint,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("attaching %s raw tracepoint: %w", tracepoint, err)
	}
	p.links = append(p.links, tpLink)
	return nil
}

func (p *probe) attachBTFTracepointProgram(ebpfProgs map[string]*cebpf.Program, name string) error {
	tpProg, ok := ebpfProgs[name]
	if !ok {
		return fmt.Errorf("%s program not found after loading", name)
	}
	tpLink, err := link.AttachTracing(link.TracingOptions{Program: tpProg})
	if err != nil {
		return fmt.Errorf("attaching sched_switch BTF tracepoint: %w", err)
	}
	p.links = append(p.links, tpLink)
	return nil
}

func closePrograms(progs map[string]*cebpf.Program) {
	for _, prog := range progs {
		_ = prog.Close()
	}
}

func (p *probe) attachTracepointKprobePrograms(ebpfProgs map[string]*cebpf.Program,
	probeCtx *tracer.ProbeContext,
) error {
	kprobeProg, ok := ebpfProgs["finish_task_switch"]
	if !ok {
		return fmt.Errorf("finish_task_switch program not found after loading")
	}

	kmod, err := probeCtx.KernelSymbolizer.Snapshot().GetModuleByName(kallsyms.Kernel)
	if err != nil {
		return fmt.Errorf("looking up kernel module: %w", err)
	}
	syms := kmod.LookupSymbolsByPrefix("finish_task_switch")
	if len(syms) == 0 {
		return fmt.Errorf("no finish_task_switch symbols found in /proc/kallsyms")
	}

	attached := false
	for _, sym := range syms {
		kl, err := link.Kprobe(string(sym.Name), kprobeProg, nil)
		if err != nil {
			log.Warnf("Failed to attach kprobe to %s: %v", sym.Name, err)
			continue
		}
		p.links = append(p.links, kl)
		attached = true
	}
	if !attached {
		return fmt.Errorf("failed to attach to any of the %d 'finish_task_switch' symbols",
			len(syms))
	}

	return p.attachTracepointProgram(ebpfProgs, "tracepoint__sched_switch_legacy")
}

func traceMapSize(configured uint32) uint32 {
	if configured > 0 {
		return configured
	}
	return defaultMapEntries
}

func (p *probe) Unload() error {
	var errs error
	for i := range p.links {
		errs = errors.Join(errs, p.links[i].Close())
	}
	p.links = nil
	return errs
}
