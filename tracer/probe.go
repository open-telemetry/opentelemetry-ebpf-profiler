// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ProbeSpec struct {
	Type     string
	Target   string
	Symbol   string
	ProgName string
}

func ParseProbe(spec string) (*ProbeSpec, error) {
	parts := strings.SplitN(spec, ":", 3)
	var progName string

	switch parts[0] {
	case "kprobe", "kretprobe":
		progName = "kprobe__generic"
		if len(parts) != 2 || parts[1] == "" {
			return nil, fmt.Errorf("invalid format: %s", spec)
		}
		return &ProbeSpec{
			Type:     parts[0],
			Symbol:   parts[1],
			ProgName: progName,
		}, nil

	case "uprobe", "uretprobe":
		progName = "uprobe__generic"
		if len(parts) != 3 || parts[2] == "" {
			return nil, fmt.Errorf("invalid format: %s", spec)
		}
		return &ProbeSpec{
			Type:     parts[0],
			Target:   parts[1],
			Symbol:   parts[2],
			ProgName: progName,
		}, nil

	default:
		return nil, fmt.Errorf("unknown probe type: %s", parts[0])
	}
}

func AttachProbe(prog *ebpf.Program, spec *ProbeSpec) (link.Link, error) {
	switch spec.Type {
	case "kprobe":
		return link.Kprobe(spec.Symbol, prog, nil)
	case "kretprobe":
		return link.Kretprobe(spec.Symbol, prog, nil)
	case "uprobe":
		ex, err := link.OpenExecutable(spec.Target)
		if err != nil {
			return nil, err
		}
		return ex.Uprobe(spec.Symbol, prog, nil)
	case "uretprobe":
		ex, err := link.OpenExecutable(spec.Target)
		if err != nil {
			return nil, err
		}
		return ex.Uretprobe(spec.Symbol, prog, nil)
	}
	return nil, fmt.Errorf("unsupported probe type")
}
