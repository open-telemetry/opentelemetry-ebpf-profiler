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
	spec      *tracer.ProbeSpec
	probeLink link.Link
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

func (g *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
	if g.probeLink != nil {
		return fmt.Errorf("kprobe already loaded")
	}
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

	g.probeLink, err = tracer.AttachProbe(prog, g.spec)
	return err
}

func (g *probe) Unload() error {
	if g.probeLink != nil {
		err := g.probeLink.Close()
		g.probeLink = nil
		return err
	}
	return nil
}
