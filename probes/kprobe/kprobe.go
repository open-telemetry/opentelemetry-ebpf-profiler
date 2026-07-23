// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package kprobe implements a custom probe that loads the generic unwinder program
// and optionally attaches it to a kernel or user-space symbol.
package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import (
	"fmt"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

// Config holds the YAML configuration for the kprobe probe.
//
//	probes:
//	  - kind: kprobe
//	    config:
//	      type: kprobe        # kprobe (default) | kretprobe | uprobe | uretprobe
//	      symbol: vfs_open
//	      target: ""          # executable path; required for uprobe/uretprobe
type Config struct {
	Type   string `mapstructure:"type"`
	Symbol string `mapstructure:"symbol"`
	Target string `mapstructure:"target"`
}

type probe struct {
	spec *tracer.ProbeSpec
}

// New validates cfg and returns a Probe backed by the generic unwinder program.
// Type defaults to "kprobe" when omitted. Symbol is always required. Target is
// required for uprobe/uretprobe. The caller is responsible for decoding the raw
// YAML value into Config.
func New(cfg Config) (tracer.Probe, error) {
	if cfg.Type == "" {
		cfg.Type = "kprobe"
	}
	if cfg.Symbol == "" {
		return nil, fmt.Errorf("kprobe: symbol is required")
	}

	probeType, err := parseProbeType(cfg.Type)
	if err != nil {
		return nil, err
	}

	if (probeType == tracer.ProbeTypeUprobe || probeType == tracer.ProbeTypeUretprobe) && cfg.Target == "" {
		return nil, fmt.Errorf("kprobe: target is required for %s", cfg.Type)
	}

	spec := &tracer.ProbeSpec{
		Type:   probeType,
		Symbol: cfg.Symbol,
		Target: cfg.Target,
	}
	return &probe{spec: spec}, nil
}

func parseProbeType(s string) (tracer.ProbeType, error) {
	switch strings.ToLower(s) {
	case "kprobe":
		return tracer.ProbeTypeKprobe, nil
	case "kretprobe":
		return tracer.ProbeTypeKretprobe, nil
	case "uprobe":
		return tracer.ProbeTypeUprobe, nil
	case "uretprobe":
		return tracer.ProbeTypeUretprobe, nil
	default:
		return 0, fmt.Errorf("unknown probe type %q: must be kprobe, kretprobe, uprobe, or uretprobe", s)
	}
}

func (g *probe) Load(reg tracer.ProbeRegistrar, ctx *tracer.ProbeContext) (link.Link, error) {
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
