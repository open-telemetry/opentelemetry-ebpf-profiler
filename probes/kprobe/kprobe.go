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
	"github.com/cilium/ebpf/link"

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

func (g *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, ctx *tracer.ProbeContext) (link.Link, error) {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	})
	if err != nil {
		return nil, fmt.Errorf("registering probe origin: %w", err)
	}

	coll, err := ctx.CollectionSpecWith(
		nil,
		[]string{progName},
		[]string{"origin_id_probe"},
	)
	if err != nil {
		return nil, err
	}

	v, ok := coll.Variables["origin_id_probe"]
	if !ok {
		return nil, fmt.Errorf("origin_id_probe variable not found in collection spec")
	}
	if err := v.Set(originID); err != nil {
		return nil, err
	}

	if err := ctx.RewriteMaps(coll, nil); err != nil {
		return nil, err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := ctx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
		{
			Name:             progName,
			NoTailCallTarget: true,
			Enable:           true,
		},
	}, 0); err != nil {
		return nil, err
	}

	prog, ok := ebpfProgs[progName]
	if !ok {
		return nil, fmt.Errorf("program %q not found after loading", progName)
	}

	return tracer.AttachProbe(prog, g.spec)
}
