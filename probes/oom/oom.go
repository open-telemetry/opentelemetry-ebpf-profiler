// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package oom implements a probe that attaches to kprobe:oom_kill_process to
// capture stack traces when the OOM killer selects a victim.
package oom // import "go.opentelemetry.io/ebpf-profiler/probes/oom"

import (
	"context"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__oom_kill_process"

// Config holds the YAML configuration for the OOM probe.
// Currently empty — no configuration required.
type Config struct{}

type probe struct{}

// New returns an OOM probe. cfg is accepted for forward compatibility but
// currently unused.
func New(_ Config) (*probe, error) {
	return &probe{}, nil
}

func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar,
	ctx *tracer.ProbeContext) error {

	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "oom_event",
		SampleUnit: "count",
	})
	if err != nil {
		return fmt.Errorf("registering oom origin: %w", err)
	}

	coll, err := ctx.CollectionSpecWith(
		nil,
		[]string{progName},
		[]string{"origin_id_oom"},
	)
	if err != nil {
		return err
	}

	v, ok := coll.Variables["origin_id_oom"]
	if !ok {
		return fmt.Errorf("origin_id_oom variable not found")
	}
	if err := v.Set(originID); err != nil {
		return fmt.Errorf("setting origin_id_oom: %w", err)
	}
	log.Infof("oom probe: origin_id_oom set to %d", originID)

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

	lnk, err := link.Kprobe("oom_kill_process", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to oom_kill_process: %w", err)
	}
	log.Infof("oom probe: kprobe attached to oom_kill_process")
	ctx.AddLink(lnk)
	return nil
}
