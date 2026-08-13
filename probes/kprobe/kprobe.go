// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package kprobe implements a custom probe that loads the generic unwinder program
// and optionally attaches it to a kernel or user-space symbol.
package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import (
	"context"
	"fmt"
	"strings"

	cebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

// Config holds the YAML configuration for the kprobe probe.
//
//	probes:
//	  - type: kprobe
//	    mode: kprobe        # kprobe (default) | kretprobe | uprobe | uretprobe
//	    symbol: vfs_open
//	    target: ""          # executable path; required for uprobe/uretprobe
type Config struct {
	Mode   string `mapstructure:"mode"`
	Symbol string `mapstructure:"symbol"`
	Target string `mapstructure:"target"`
}

type probe struct {
	spec *tracer.ProbeSpec
}

// New validates cfg and returns a Probe backed by the generic unwinder program.
// Mode defaults to "kprobe" when omitted. Symbol is always required. Target is
// required for uprobe/uretprobe. The caller is responsible for decoding the raw
// YAML value into Config.
func New(cfg Config) (*probe, error) {
	if cfg.Mode == "" {
		cfg.Mode = "kprobe"
	}
	if cfg.Symbol == "" {
		return nil, fmt.Errorf("kprobe: symbol is required")
	}

	probeMode, err := parseProbeMode(cfg.Mode)
	if err != nil {
		return nil, err
	}

	if (probeMode == tracer.ProbeModeUprobe || probeMode == tracer.ProbeModeUretprobe) && cfg.Target == "" {
		return nil, fmt.Errorf("kprobe: target is required for %s", cfg.Mode)
	}

	spec := &tracer.ProbeSpec{
		Mode:   probeMode,
		Symbol: cfg.Symbol,
		Target: cfg.Target,
	}
	return &probe{spec: spec}, nil
}

func parseProbeMode(s string) (tracer.ProbeMode, error) {
	switch strings.ToLower(s) {
	case "kprobe":
		return tracer.ProbeModeKprobe, nil
	case "kretprobe":
		return tracer.ProbeModeKretprobe, nil
	case "uprobe":
		return tracer.ProbeModeUprobe, nil
	case "uretprobe":
		return tracer.ProbeModeUretprobe, nil
	default:
		return 0, fmt.Errorf("unknown probe type %q: must be kprobe, kretprobe, uprobe, or uretprobe", s)
	}
}

func (g *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	})
	if err != nil {
		return fmt.Errorf("registering probe origin: %w", err)
	}

	coll, err := probeCtx.CollectionSpecWith(
		nil,
		[]string{progName},
		[]string{"origin_id_probe"},
	)
	if err != nil {
		return err
	}

	v, ok := coll.Variables["origin_id_probe"]
	if !ok {
		return fmt.Errorf("origin_id_probe variable not found in collection spec")
	}
	if err := v.Set(originID); err != nil {
		return err
	}

	if err := probeCtx.RewriteMaps(coll, nil); err != nil {
		return err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{
			Name:             progName,
			NoTailCallTarget: true,
			Enable:           true,
		},
	}, 0); err != nil {
		return err
	}

	prog, ok := ebpfProgs[progName]
	if !ok {
		return fmt.Errorf("program %q not found after loading", progName)
	}

	lnk, err := tracer.AttachProbe(prog, g.spec)
	if err != nil {
		return err
	}
	probeCtx.AddLink(lnk)
	return nil
}
