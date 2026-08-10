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

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Config holds the YAML configuration for the off-CPU probe.
//
//	probes:
//	  - type: offcpu
//	    threshold: 0.1   # capture probability in ]0.0, 1.0]
type Config struct {
	Threshold float64 `mapstructure:"threshold"`
}

type probe struct {
	threshold uint32
}

// New validates cfg and returns an off-CPU profiling Probe.
// Threshold is a capture probability in ]0.0, 1.0]. 1.0 captures every event.
func New(cfg Config) (*probe, error) {
	if cfg.Threshold <= 0.0 || cfg.Threshold > 1.0 {
		return nil, fmt.Errorf("offcpu: threshold %f is out of range ]0.0, 1.0]", cfg.Threshold)
	}
	return &probe{threshold: uint32(cfg.Threshold * math.MaxUint32)}, nil
}

func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) (link.Link, error) {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType:   "off_cpu",
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	})
	if err != nil {
		return nil, fmt.Errorf("registering off-CPU origin: %w", err)
	}

	coll, err := probeCtx.CollectionSpecWith(
		[]string{"sched_times"},
		[]string{"finish_task_switch", "tracepoint__sched_switch"},
		[]string{"off_cpu_threshold", "origin_id_off_cpu"},
	)
	if err != nil {
		return nil, err
	}

	if err := coll.Variables["off_cpu_threshold"].Set(p.threshold); err != nil {
		return nil, fmt.Errorf("set off_cpu_threshold: %w", err)
	}
	if err := coll.Variables["origin_id_off_cpu"].Set(originID); err != nil {
		return nil, fmt.Errorf("set origin_id_off_cpu: %w", err)
	}

	// Resize sched_times proportionally to the capture probability so that
	// infrequent sampling doesn't waste memory and heavy sampling doesn't drop events.
	coll.Maps["sched_times"].MaxEntries = schedTimesSize(p.threshold)

	schedMap, err := cebpf.NewMap(coll.Maps["sched_times"])
	if err != nil {
		return nil, fmt.Errorf("creating sched_times map: %w", err)
	}
	defer schedMap.Close()

	if err := probeCtx.RewriteMaps(coll, map[string]*cebpf.Map{"sched_times": schedMap}); err != nil {
		return nil, err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{Name: "finish_task_switch", NoTailCallTarget: true, Enable: true},
		{Name: "tracepoint__sched_switch", NoTailCallTarget: true, Enable: true},
	}, 0); err != nil {
		return nil, err
	}

	return attachPrograms(ebpfProgs)
}

// attachPrograms attaches the loaded eBPF programs to the scheduler hooks and
// returns a composite link that closes all attachments on Close.
func attachPrograms(ebpfProgs map[string]*cebpf.Program) (link.Link, error) {
	kprobeProg, ok := ebpfProgs["finish_task_switch"]
	if !ok {
		return nil, fmt.Errorf("finish_task_switch program not found after loading")
	}
	tpProg, ok := ebpfProgs["tracepoint__sched_switch"]
	if !ok {
		return nil, fmt.Errorf("tracepoint__sched_switch program not found after loading")
	}

	syms, err := finishTaskSwitchSymbols()
	if err != nil {
		return nil, fmt.Errorf("looking up finish_task_switch symbols: %w", err)
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("no finish_task_switch symbols found in /proc/kallsyms")
	}

	var kprobeLinks []link.Link
	for _, sym := range syms {
		kl, err := link.Kprobe(string(sym.Name), kprobeProg, nil)
		if err != nil {
			log.Warnf("Failed to attach kprobe to %s: %v", sym.Name, err)
			continue
		}
		kprobeLinks = append(kprobeLinks, kl)
	}
	if len(kprobeLinks) == 0 {
		return nil, fmt.Errorf("failed to attach kprobe to any of %d finish_task_switch symbol(s)", len(syms))
	}

	tpLink, err := link.Tracepoint("sched", "sched_switch", tpProg, nil)
	if err != nil {
		for _, l := range kprobeLinks {
			l.Close()
		}
		return nil, fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}

	return &multiLink{Link: tpLink, extras: kprobeLinks}, nil
}

// multiLink embeds a primary link.Link and adds extra links that are closed
// together with the primary. Embedding satisfies the link.Link interface
type multiLink struct {
	link.Link
	extras []link.Link
}

func (m *multiLink) Close() error {
	var e error
	if err := m.Link.Close(); err != nil {
		e = errors.Join(e, err)
	}
	for _, l := range m.extras {
		if err := l.Close(); err != nil {
			e = errors.Join(e, err)
		}
	}
	return e
}

// finishTaskSwitchSymbols returns all kernel symbols whose name starts with
// "finish_task_switch" by loading a fresh kallsyms snapshot.
func finishTaskSwitchSymbols() ([]*libpf.Symbol, error) {
	s, err := kallsyms.NewSymbolizer()
	if err != nil {
		return nil, err
	}
	kmod, err := s.Snapshot().GetModuleByName(kallsyms.Kernel)
	if err != nil {
		return nil, err
	}
	return kmod.LookupSymbolsByPrefix("finish_task_switch"), nil
}

// schedTimesSize calculates the size of the sched_times map based on the
// configured off-cpu threshold. Assumes an upper bound of 1000 Hz scheduler
// events and 3s average off-CPU time, scaled by the capture probability.
// Result is clamped to [16, 4096].
func schedTimesSize(threshold uint32) uint32 {
	size := uint32((4096 * uint64(threshold)) / math.MaxUint32)
	if size < 16 {
		return 16
	}
	if size > 4096 {
		return 4096
	}
	return size
}
