// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package generic implements a custom probe that loads the generic unwinder program
// and optionally attaches it to a kernel or user-space symbol.
package generic // import "go.opentelemetry.io/ebpf-profiler/probes/generic"

import (
	"fmt"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

// GenericConfig holds the YAML configuration for the generic probe.
//
//	custom_probes:
//	  generic:
//	    type: kprobe          # kprobe | kretprobe | uprobe | uretprobe
//	    symbol: vfs_open
//	    target: ""            # executable path; required for uprobe/uretprobe
//
// Because custom_probes is keyed by probe type name, only one generic probe can
// be configured at a time.
type GenericConfig struct {
	Type   string `mapstructure:"type"`
	Symbol string `mapstructure:"symbol"`
	Target string `mapstructure:"target"`
}

type genericProbe struct {
	spec *tracer.ProbeSpec
}

// New validates cfg and returns a Probe backed by the generic unwinder program.
// Type and Symbol are always required. Target is required for uprobe/uretprobe.
// The caller is responsible for decoding the raw YAML value into GenericConfig.
func New(cfg GenericConfig) (tracer.Probe, error) {
	if cfg.Type == "" {
		return nil, fmt.Errorf("generic probe: type is required")
	}
	if cfg.Symbol == "" {
		return nil, fmt.Errorf("generic probe: symbol is required")
	}

	probeType, err := parseProbeType(cfg.Type)
	if err != nil {
		return nil, err
	}

	if (probeType == tracer.ProbeTypeUprobe || probeType == tracer.ProbeTypeUretprobe) && cfg.Target == "" {
		return nil, fmt.Errorf("generic probe: target is required for %s", cfg.Type)
	}

	spec := &tracer.ProbeSpec{
		Type:   probeType,
		Symbol: cfg.Symbol,
		Target: cfg.Target,
	}
	return &genericProbe{spec: spec}, nil
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

func (g *genericProbe) Load(originID uint16, ctx *tracer.ProbeContext) (link.Link, error) {
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

func (g *genericProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	}
}
