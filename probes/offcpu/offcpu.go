// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package offcpu provides a custom probe that reports sampling
// based off CPU events.
package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"errors"
	"fmt"
	"math"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type OffCPUCfg struct {
	Threshold float64
}

type offCPUReporter struct {
	threshold uint32
	ebpfMaps  map[string]*cebpf.Map
	ebpfProgs map[string]*cebpf.Program
	originID  libpf.Origin
}

// attachedLink wraps multiple links to manage them together.
// It embeds the primary link to satisfy the link.Link interface,
// and keeps references to others so they don't get garbage collected.
type attachedLink struct {
	link.Link
	others []link.Link
}

func (al *attachedLink) Close() error {
	var lastErr error
	if err := al.Link.Close(); err != nil {
		lastErr = err
	}
	for _, l := range al.others {
		if err := l.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func New(tmpCfg any) (tracer.Probe, error) {
	cfgMap, ok := tmpCfg.(map[string]any)
	if !ok {
		return nil, errors.New("invalid config")
	}

	cfg := &OffCPUCfg{}
	if threshold, ok := cfgMap["threshold"].(float64); ok {
		cfg.Threshold = threshold
	} else {
		return nil, fmt.Errorf("threshold is missing")
	}

	if cfg.Threshold < 0.0 || cfg.Threshold > 1.0 {
		return nil, errors.New(
			"invalid argument for off-cpu threshold. The value " +
				"should be in the range [0..1].")
	}

	probe := &offCPUReporter{
		threshold: uint32(cfg.Threshold * float64(math.MaxUint32)),
		ebpfMaps:  make(map[string]*cebpf.Map),
		ebpfProgs: make(map[string]*cebpf.Program),
	}

	return probe, nil
}

func (o *offCPUReporter) Load(originID libpf.Origin, maps tracer.TracerMaps, systemVars *tracer.SystemVariables) (link.Link, error) {
	o.originID = originID

	if systemVars == nil {
		return nil, fmt.Errorf("system variables are missing")
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	// Build the collection with maps and programs
	_, ebpfMaps, ebpfProgs, err := o.buildCollection(maps, systemVars, originID)
	if err != nil {
		return nil, err
	}

	// Store maps and programs
	o.ebpfMaps = ebpfMaps
	o.ebpfProgs = ebpfProgs

	// Link the eBPF programs to their kernel hooks
	l, err := o.linkPrograms(ebpfProgs)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (o *offCPUReporter) buildCollection(maps tracer.TracerMaps, systemVars *tracer.SystemVariables, originID libpf.Origin) (*cebpf.CollectionSpec, map[string]*cebpf.Map, map[string]*cebpf.Program, error) {
	// Use CollectionSpecWith to get a pre-populated spec with necessary maps, programs, and variables
	coll, err := tracer.CollectionSpecWith(
		[]string{"sched_times"},
		[]string{"finish_task_switch", "tracepoint__sched_switch"},
		[]string{"off_cpu_threshold", "origin_id_off_cpu"},
		systemVars,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create collection spec: %v", err)
	}

	// Set the off-cpu threshold and origin ID variables
	if err := coll.Variables["off_cpu_threshold"].Set(o.threshold); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set off_cpu_threshold: %v", err)
	}

	if err := coll.Variables["origin_id_off_cpu"].Set(uint32(originID)); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set origin_id_off_cpu: %v", err)
	}

	// Customize sched_times map size based on the threshold
	if mapSpec, ok := coll.Maps["sched_times"]; ok {
		mapSpec.MaxEntries = schedTimesSize(o.threshold)
	} else {
		return nil, nil, nil, fmt.Errorf("missing map sched_times")
	}

	if err = tracer.SyncVariablesToMapSpecs(coll); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sync variables to map specs: %v", err)
	}

	// Get required tailcall maps
	kprobeProgsMap, ok := maps["kprobe_progs"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("kprobe_progs map not found in loaded maps")
	}

	perfProgsMap, ok := maps["perf_progs"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("perf_progs map not found in loaded maps")
	}

	ebpfMaps := make(map[string]*cebpf.Map)
	for mapName := range coll.Maps {
		mapSpec := coll.Maps[mapName]
		m, err := cebpf.NewMap(mapSpec)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load %s map: %v", mapName, err)
		}
		ebpfMaps[mapName] = m
	}

	rewrites := map[string]*cebpf.Map{
		"interpreter_offsets":      maps["interpreter_offsets"],
		"metrics":                  maps["metrics"],
		"pid_page_to_mapping_info": maps["pid_page_to_mapping_info"],
		"reported_pids":            maps["reported_pids"],
		"per_cpu_records":          maps["per_cpu_records"],
		"report_events":            maps["report_events"],
		"inhibit_events":           maps["inhibit_events"],
		"pid_events":               maps["pid_events"],
		"sched_times":              ebpfMaps["sched_times"],
		".rodata.var":              ebpfMaps[".rodata.var"],
		"perf_progs":               maps["kprobe_progs"],
	}
	if err = tracer.RewriteMaps(coll, rewrites); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	// Off-CPU programs will tail-call into perf_progs, which has all unwinders
	ebpfProgs := make(map[string]*cebpf.Program)

	// Load only the off-CPU entry points (finish_task_switch, tracepoint__sched_switch).
	// The tail-call targets (unwinders) are already loaded in kprobe_progs above.
	offCPUProgs := []tracer.ProgLoaderHelper{
		{
			Name:             "finish_task_switch",
			NoTailCallTarget: true,
			Enable:           true,
		},
		{
			Name:             "tracepoint__sched_switch",
			NoTailCallTarget: true,
			Enable:           true,
		},
	}

	if err = tracer.LoadProbeUnwinders(coll, ebpfProgs, kprobeProgsMap, offCPUProgs, 0, perfProgsMap.FD()); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load offcpu eBPF programs: %v", err)
	}

	return coll, ebpfMaps, ebpfProgs, nil
}

func (o *offCPUReporter) linkPrograms(ebpfProgs map[string]*cebpf.Program) (link.Link, error) {
	var links []link.Link

	// Attach finish_task_switch kprobe with fallback to alternative symbols
	// finish_task_switch may not be exported on all kernels, so try alternatives
	if prog, ok := ebpfProgs["finish_task_switch"]; ok {
		symbolizer, err := kallsyms.NewSymbolizer()
		if err != nil {
			return nil, fmt.Errorf("failed to read kernel symbols: %v", err)
		}

		kmod, err := symbolizer.GetModuleByName(kallsyms.Kernel)
		if err != nil {
			return nil, fmt.Errorf("failed to get kernel module: %v", err)
		}

		symbols := []string{"finish_task_switch", "__switch_to", "schedule_tail"}
		var attached bool

		for _, hookSymbolPrefix := range symbols {
			kprobeSymbols := kmod.LookupSymbolsByPrefix(hookSymbolPrefix)
			if len(kprobeSymbols) == 0 {
				continue
			}

			symbolName := string(kprobeSymbols[0].Name)
			l, err := link.Kprobe(symbolName, prog, nil)
			if err != nil {
				continue
			}

			links = append(links, l)
			attached = true
			break
		}

		if !attached {
			return nil, fmt.Errorf(
				"failed to attach finish_task_switch program to any kernel symbol "+
					"(tried: %v): off-CPU profiling requires one of these symbols to be available",
				symbols)
		}
	}

	// Attach tracepoint__sched_switch tracepoint
	if prog, ok := ebpfProgs["tracepoint__sched_switch"]; ok {
		l, err := link.Tracepoint("sched", "sched_switch", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach sched_switch tracepoint: %v", err)
		}
		links = append(links, l)
	}

	if len(links) == 0 {
		return nil, errors.New("no links attached")
	}
	return &attachedLink{
		Link:   links[0],
		others: links[1:],
	}, nil
}

func (o *offCPUReporter) ReportMetadata() tracer.ReporterMetadata {
	return tracer.ReporterMetadata{
		Typ:          "off_cpu",
		Unit:         "nanoseconds",
		ReportValues: true,
	}
}

// schedTimesSize calculates the size of the sched_times map based on the
// configured off-cpu threshold.
// To not lose too many scheduling events but also not oversize sched_times,
// calculate a size based on an assumed upper bound of scheduler events per
// second (1000hz) multiplied by an average time a task remains off CPU (3s),
// scaled by the probability of capturing a trace.
func schedTimesSize(threshold uint32) uint32 {
	size := uint32((4096 * uint64(threshold)) / math.MaxUint32)
	if size < 16 {
		// Guarantee a minimal size of 16.
		return 16
	}
	if size > 4096 {
		// Guarantee a maximum size of 4096.
		return 4096
	}
	return size
}
