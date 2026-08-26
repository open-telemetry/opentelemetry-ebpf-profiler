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

// Config holds the YAML configuration for the kprobe extension.
//
//	extensions:
//	  kprobe/vfs_open:
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

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	if c.Symbol == "" {
		return fmt.Errorf("kprobe: symbol is required")
	}
	mode := c.Mode
	if mode == "" {
		mode = "kprobe"
	}
	probeMode, err := parseProbeMode(mode)
	if err != nil {
		return err
	}
	if (probeMode == tracer.ProbeModeUprobe || probeMode == tracer.ProbeModeUretprobe) && c.Target == "" {
		return fmt.Errorf("kprobe: target is required for %s", mode)
	}
	return nil
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

func (g *probe) SampleType() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	}
}

const (
	ctxMapName      = "probe_value"
	tailCallMapName = "collect_trace_trampoline"
)

func (g *probe) Load(_ context.Context, probeCtx *tracer.ProbeContext) error {
	coll, err := probeCtx.CollectionSpecWith(
		[]string{ctxMapName, tailCallMapName},
		[]string{progName},
		nil,
	)
	if err != nil {
		return err
	}

	if err := probeCtx.WireTrampoline(coll, ctxMapName, tailCallMapName); err != nil {
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
