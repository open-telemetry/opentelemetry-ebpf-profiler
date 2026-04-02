// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package oomreporter provides a costum probe that attaches
// to kprobe:oom_kill_process to trigger stack unwinding for
// processes that get killed because they are out of memory.
package oom // import "go.opentelemetry.io/ebpf-profiler/probes/oom"

import (
	"errors"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type oomReporter struct {
	originID  libpf.Origin
	ebpfMaps  map[string]*cebpf.Map
	ebpfProgs map[string]*cebpf.Program
}

func New(_ any) (tracer.Probe, error) {
	probe := &oomReporter{
		ebpfMaps:  make(map[string]*cebpf.Map),
		ebpfProgs: make(map[string]*cebpf.Program),
	}
	return probe, nil
}

func (o *oomReporter) Load(originID libpf.Origin, maps tracer.TracerMaps, systemVars *tracer.SystemVariables) (link.Link, error) {
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

func (o *oomReporter) buildCollection(maps tracer.TracerMaps, systemVars *tracer.SystemVariables, originID libpf.Origin) (*cebpf.CollectionSpec, map[string]*cebpf.Map, map[string]*cebpf.Program, error) {
	// Use CollectionSpecWith to get a pre-populated spec with necessary maps, programs, and variables
	coll, err := tracer.CollectionSpecWith(
		[]string{},
		[]string{"oom_kill_process"},
		[]string{"origin_id_oom"},
		systemVars,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create collection spec: %v", err)
	}

	// Set the origin ID variable
	if err := coll.Variables["origin_id_oom"].Set(uint32(originID)); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set origin_id_oom: %v", err)
	}

	if err = tracer.SyncVariablesToMapSpecs(coll); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sync variables to map specs: %v", err)
	}

	// Get required tailcall maps
	kprobeProgsMap, ok := maps["kprobe_progs"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("kprobe_progs map not found in loaded maps")
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
		".rodata.var":              ebpfMaps[".rodata.var"],
		"perf_progs":               maps["kprobe_progs"],
	}
	if err = tracer.RewriteMaps(coll, rewrites); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	// OOM program will tail-call into perf_progs, which has all unwinders
	ebpfProgs := make(map[string]*cebpf.Program)

	// Load only the OOM entry point (oom_kill_process).
	// The tail-call targets (unwinders) are already loaded in kprobe_progs above.
	oomProgs := []tracer.ProgLoaderHelper{
		{
			Name:             "oom_kill_process",
			NoTailCallTarget: true,
			Enable:           true,
		},
	}

	if err = tracer.LoadProbeUnwinders(coll, ebpfProgs, kprobeProgsMap, oomProgs, 0, maps["kprobe_progs"].FD()); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load oom eBPF programs: %v", err)
	}

	return coll, ebpfMaps, ebpfProgs, nil
}

func (o *oomReporter) linkPrograms(ebpfProgs map[string]*cebpf.Program) (link.Link, error) {
	// Attach oom_kill_process kprobe
	if prog, ok := ebpfProgs["oom_kill_process"]; ok {
		l, err := link.Kprobe("oom_kill_process", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach oom_kill_process kprobe: %v", err)
		}
		return l, nil
	}

	return nil, errors.New("oom_kill_process program not loaded")
}

func (o *oomReporter) ReportMetadata() tracer.ReporterMetadata {
	return tracer.ReporterMetadata{
		Typ:  "oom_event",
		Unit: "count",
	}
}
