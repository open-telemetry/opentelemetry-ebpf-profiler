// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package offcpu implements an off-CPU profiling probe that records how long
// tasks spend blocked off-CPU between scheduler context switches.
package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"context"
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
	// MaxMapEntries caps pending trace payloads at approximately 1 GiB.
	MaxMapEntries = (1 << 30) / support.Sizeof_Trace

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
//	     mode: tracepoint    # or tracepoint-kprobe; empty defaults to tracepoint
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
	case "", ModeTracepoint:
		return p.loadTracepoint(originID, probeCtx)
	case ModeTracepointKprobe:
		return p.loadTracepointKprobe(originID, probeCtx)
	default:
		return fmt.Errorf("unsupported off-CPU mode %q", p.mode)
	}
}

func (p *probe) loadTracepoint(originID uint16, probeCtx *tracer.ProbeContext) error {
	if err := p.loadTracepointVariant(originID, probeCtx, true); err == nil {
		return nil
	} else {
		log.Warnf("BTF sched_switch tracepoint unavailable, falling back to regular tracepoint: %v", err)
	}
	return p.loadTracepointVariant(originID, probeCtx, false)
}

func (p *probe) loadTracepointVariant(originID uint16, probeCtx *tracer.ProbeContext,
	useBTF bool,
) error {
	entryProgram := "tracepoint__sched_switch"
	if useBTF {
		entryProgram = "tp_btf__sched_switch"
	}
	coll, err := probeCtx.CollectionSpecWithUnwinders(
		[]string{"off_cpu_traces", "tracepoint_progs"},
		[]string{entryProgram},
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

	coll.Maps["off_cpu_traces"].MaxEntries = traceMapSize(p.mapEntries)

	traceMap, err := cebpf.NewMap(coll.Maps["off_cpu_traces"])
	if err != nil {
		return fmt.Errorf("creating off_cpu_traces map: %w", err)
	}
	defer traceMap.Close()

	tailcallMap, err := cebpf.NewMap(coll.Maps["tracepoint_progs"])
	if err != nil {
		return fmt.Errorf("creating tracepoint_progs map: %w", err)
	}
	defer tailcallMap.Close()

	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{
		"off_cpu_traces":   traceMap,
		"tracepoint_progs": tailcallMap,
	}); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	defer closePrograms(ebpfProgs)
	entry := []tracer.ProgLoaderHelper{
		{Name: entryProgram, NoTailCallTarget: true, Enable: true},
	}
	if useBTF {
		err = probeCtx.LoadBTFTracepointUnwinders(coll, ebpfProgs, tailcallMap, entry, 0)
	} else {
		err = probeCtx.LoadTracepointUnwinders(coll, ebpfProgs, tailcallMap, entry, 0)
	}
	if err != nil {
		return err
	}

	if useBTF {
		return attachBTFTracepointProgram(ebpfProgs, entryProgram, probeCtx)
	}
	return attachTracepointProgram(ebpfProgs, entryProgram, probeCtx)
}

func (p *probe) loadTracepointKprobe(originID uint16, probeCtx *tracer.ProbeContext) error {
	coll, err := probeCtx.CollectionSpecWithProbeUnwinders(
		[]string{"sched_times"},
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
	coll.Maps["sched_times"].MaxEntries = traceMapSize(p.mapEntries)

	schedMap, err := cebpf.NewMap(coll.Maps["sched_times"])
	if err != nil {
		return fmt.Errorf("creating sched_times map: %w", err)
	}
	defer schedMap.Close()
	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{"sched_times": schedMap}); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{Name: "finish_task_switch", NoTailCallTarget: true, Enable: true},
		{Name: "tracepoint__sched_switch_legacy", NoTailCallTarget: true, Enable: true},
	}, 0); err != nil {
		return err
	}

	return attachTracepointKprobePrograms(ebpfProgs, probeCtx)
}

func attachTracepointProgram(ebpfProgs map[string]*cebpf.Program, name string,
	probeCtx *tracer.ProbeContext,
) error {
	tpProg, ok := ebpfProgs[name]
	if !ok {
		return fmt.Errorf("%s program not found after loading", name)
	}

	tpLink, err := link.Tracepoint("sched", "sched_switch", tpProg, nil)
	if err != nil {
		return fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}
	probeCtx.AddLink(tpLink)

	return nil
}

func attachBTFTracepointProgram(ebpfProgs map[string]*cebpf.Program, name string,
	probeCtx *tracer.ProbeContext,
) error {
	tpProg, ok := ebpfProgs[name]
	if !ok {
		return fmt.Errorf("%s program not found after loading", name)
	}
	tpLink, err := link.AttachTracing(link.TracingOptions{Program: tpProg})
	if err != nil {
		return fmt.Errorf("attaching sched_switch BTF tracepoint: %w", err)
	}
	probeCtx.AddLink(tpLink)
	return nil
}

func closePrograms(progs map[string]*cebpf.Program) {
	for _, prog := range progs {
		_ = prog.Close()
	}
}

func attachTracepointKprobePrograms(ebpfProgs map[string]*cebpf.Program,
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
		probeCtx.AddLink(kl)
		attached = true
	}
	if !attached {
		return fmt.Errorf("failed to attach to any of the %d 'finish_task_switch' symbols",
			len(syms))
	}

	return attachTracepointProgram(ebpfProgs, "tracepoint__sched_switch_legacy", probeCtx)
}

func traceMapSize(configured uint32) uint32 {
	if configured > 0 {
		return configured
	}
	return defaultMapEntries
}
