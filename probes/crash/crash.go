// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package crash implements a probe that attaches to kprobe:do_coredump to
// capture stack traces when processes die from fatal signals (SIGSEGV,
// SIGBUS, SIGABRT, SIGFPE, SIGILL).
package crash // import "go.opentelemetry.io/ebpf-profiler/probes/crash"

import (
	"context"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__do_coredump"

// Config holds the YAML configuration for the crash probe.
// Currently empty — no configuration required.
type Config struct{}

type probe struct{}

// New returns a crash probe. cfg is accepted for forward compatibility but
// currently unused.
func New(_ Config) (*probe, error) {
	return &probe{}, nil
}

func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar,
	ctx *tracer.ProbeContext) error {

	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "crash_event",
		SampleUnit: "count",
	})
	if err != nil {
		return fmt.Errorf("registering crash origin: %w", err)
	}

	coll, err := ctx.CollectionSpecWith(
		nil,                         // no extra maps
		[]string{progName},          // BPF program
		[]string{"origin_id_crash"}, // RODATA variable
	)
	if err != nil {
		return err
	}

	v, ok := coll.Variables["origin_id_crash"]
	if !ok {
		return fmt.Errorf("origin_id_crash variable not found")
	}
	if err := v.Set(originID); err != nil {
		return fmt.Errorf("setting origin_id_crash: %w", err)
	}
	log.Infof("crash probe: origin_id_crash set to %d", originID)

	if err := ctx.RewriteMaps(coll, nil); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := ctx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{Name: progName, NoTailCallTarget: true, Enable: true},
	}, 0); err != nil {
		return err
	}

	prog, ok := ebpfProgs[progName]
	if !ok {
		return fmt.Errorf("program %q not found after loading", progName)
	}

	lnk, err := link.Kprobe("do_coredump", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to do_coredump: %w", err)
	}
	log.Infof("crash probe: kprobe attached to do_coredump")
	ctx.AddLink(lnk)
	return nil
}
