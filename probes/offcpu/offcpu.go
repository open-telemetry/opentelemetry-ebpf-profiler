// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package offcpu implements an off-CPU profiling probe that records how long
// tasks spend blocked off-CPU between scheduler context switches.
package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// Upper bound for an explicitly configured max_tracked_threads.
	maxTrackedThreadsCap = 1 << 20
)

// Config holds the YAML configuration for the off-CPU probe.
//
//	extensions:
//	  offcpu:
//	    threshold: 0.1            # capture probability in ]0.0, 1.0]
//	    min_duration: 0s          # optional; 0 = keep all sampled waits.
//	                              # Drops shorter off-CPU waits before stack unwinding.
//	    max_tracked_threads: 0    # optional; 0 = auto from threshold ([16, 4096]).
//	                              # Bounds how many off-CPU threads are tracked concurrently.
type Config struct {
	Threshold         float64       `mapstructure:"threshold"`
	MinDuration       time.Duration `mapstructure:"min_duration"`
	MaxTrackedThreads uint32        `mapstructure:"max_tracked_threads"`
}

// Validate implements confmap.Validator.
func (cfg *Config) Validate() error {
	if cfg.Threshold <= 0.0 || cfg.Threshold > 1.0 {
		return fmt.Errorf("offcpu: threshold %f is out of range ]0.0, 1.0]", cfg.Threshold)
	}
	if cfg.MinDuration < 0 {
		return fmt.Errorf("offcpu: min_duration %s must be >= 0", cfg.MinDuration)
	}
	if cfg.MaxTrackedThreads > maxTrackedThreadsCap {
		return fmt.Errorf("offcpu: max_tracked_threads %d exceeds maximum %d",
			cfg.MaxTrackedThreads, maxTrackedThreadsCap)
	}
	return nil
}

type probe struct {
	threshold         uint32
	minDuration       time.Duration
	maxTrackedThreads uint32
	links             []link.Link
}

func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	originID, err := reg.Register(&pm.OriginEntry{
		Meta: &samples.TypeMetadata{
			SampleTypes:  []samples.SampleType{{Type: "off_cpu", Unit: "nanoseconds"}},
			ReportValues: true,
			AppendValues: samples.AppendFirstContextValue,
		},
	})
	if err != nil {
		return fmt.Errorf("registering off-CPU origin: %w", err)
	}

	coll, err := probeCtx.CollectionSpecWith(
		[]string{"sched_times"},
		[]string{"finish_task_switch", "tracepoint__sched_switch"},
		[]string{"off_cpu_threshold", "off_cpu_min_duration_ns", "origin_id_off_cpu"},
	)
	if err != nil {
		return err
	}

	if err := coll.Variables["off_cpu_threshold"].Set(p.threshold); err != nil {
		return fmt.Errorf("set off_cpu_threshold: %w", err)
	}
	if err := coll.Variables["off_cpu_min_duration_ns"].Set(uint64(p.minDuration.Nanoseconds())); err != nil {
		return fmt.Errorf("set off_cpu_min_duration_ns: %w", err)
	}
	if err := coll.Variables["origin_id_off_cpu"].Set(originID); err != nil {
		return fmt.Errorf("set origin_id_off_cpu: %w", err)
	}

	// Resize sched_times: use the configured size when set, otherwise scale
	// with capture probability so infrequent sampling does not waste memory
	// and heavy sampling does not drop events.
	maxEntries := p.schedTimesMaxEntries()
	coll.Maps["sched_times"].MaxEntries = maxEntries
	log.Debugf("offcpu: sched_times max_entries=%d", maxEntries)

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
		{Name: "tracepoint__sched_switch", NoTailCallTarget: true, Enable: true},
	}, 0); err != nil {
		return err
	}

	return p.attachPrograms(ebpfProgs, probeCtx)
}

// attachPrograms attaches the loaded eBPF programs to the scheduler hooks and
// stores the resulting links.
func (p *probe) attachPrograms(ebpfProgs map[string]*cebpf.Program, probeCtx *tracer.ProbeContext) error {
	kprobeProg, ok := ebpfProgs["finish_task_switch"]
	if !ok {
		return fmt.Errorf("finish_task_switch program not found after loading")
	}
	tpProg, ok := ebpfProgs["tracepoint__sched_switch"]
	if !ok {
		return fmt.Errorf("tracepoint__sched_switch program not found after loading")
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
	// Attach to all symbols with the prefix finish_task_switch.
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

	tpLink, err := link.Tracepoint("sched", "sched_switch", tpProg, nil)
	if err != nil {
		return fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}
	p.links = append(p.links, tpLink)

	return nil
}

// schedTimesMaxEntries returns the max_entries for the sched_times map.
func (p *probe) schedTimesMaxEntries() uint32 {
	if p.maxTrackedThreads != 0 {
		return p.maxTrackedThreads
	}
	return autoSchedTimesSize(p.threshold)
}

// autoSchedTimesSize calculates the size of the sched_times map based on the
// configured off-cpu threshold. Assumes an upper bound of 1000 Hz scheduler
// events and 3s average off-CPU time, scaled by the capture probability.
// Result is clamped to [16, 4096].
func autoSchedTimesSize(threshold uint32) uint32 {
	size := uint32((4096 * uint64(threshold)) / math.MaxUint32)
	if size < 16 {
		return 16
	}
	if size > 4096 {
		return 4096
	}
	return size
}

func (p *probe) Unload() error {
	var errs error
	for i := range p.links {
		errs = errors.Join(errs, p.links[i].Close())
	}
	p.links = nil
	return errs
}
