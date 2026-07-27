// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package uprobe implements a per-process probe that attaches a PID-filtered uprobe
// to every process that maps a given target executable or shared library.
//
// A OTel config using this approach could look like this:
//
//	receivers:
//	  profiling:
//	    probes:
//	      - kind: uprobe
//	        config:
//	          target: /usr/lib/x86_64-linux-gnu/libc.so.6
//	          symbol: malloc
package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

type Config struct {
	Target string `mapstructure:"target"`
	Symbol string `mapstructure:"symbol"`
}

type probe struct {
	target string
	symbol string

	// prog is the shared eBPF program loaded once in Load, reused across Attach calls.
	prog *cebpf.Program

	mu    sync.Mutex
	links map[libpf.PID]link.Link
}

func New(cfg Config) (tracer.Probe, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("uprobe: target is required")
	}
	if cfg.Symbol == "" {
		return nil, fmt.Errorf("uprobe: symbol is required")
	}
	return &probe{
		target: cfg.Target,
		symbol: cfg.Symbol,
		links:  make(map[libpf.PID]link.Link),
	}, nil
}

// Load implements tracer.Probe. It loads the shared eBPF program once and registers
// the probe as a per-process attacher so that SynchronizeProcess drives per-PID
// attachment rather than a single system-wide link.
func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) (link.Link, error) {
	originID, err := reg.Register(&samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	})
	if err != nil {
		return nil, fmt.Errorf("registering probe origin: %w", err)
	}

	coll, err := probeCtx.CollectionSpecWith(
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

	if err := probeCtx.RewriteMaps(coll, nil); err != nil {
		return nil, err
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	if err := probeCtx.LoadProbeUnwinders(coll, ebpfProgs, []tracer.ProgLoaderHelper{
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
	p.prog = prog

	// Register for per-process callbacks instead of returning a global link.
	probeCtx.RegisterProbeAttacher(p)
	return nil, nil
}

// Match implements processmanager.ProbeAttacher.
func (p *probe) Match(mappingPath string) bool {
	return mappingPath == p.target ||
		filepath.Base(mappingPath) == filepath.Base(p.target)
}

// Attach implements processmanager.ProbeAttacher. Opens a PID-restricted uprobe
// for the given process and stores the link for later cleanup.
func (p *probe) Attach(pid libpf.PID) error {
	ex, err := link.OpenExecutable(p.target)
	if err != nil {
		return fmt.Errorf("open %s: %w", p.target, err)
	}

	lnk, err := ex.Uprobe(p.symbol, p.prog, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		return fmt.Errorf("uprobe %s:%s pid %d: %w", p.target, p.symbol, pid, err)
	}

	p.mu.Lock()
	p.links[pid] = lnk
	p.mu.Unlock()
	return nil
}

// Detach implements processmanager.ProbeAttacher. Closes the PID-restricted uprobe
// link for the exiting process.
func (p *probe) Detach(pid libpf.PID) {
	p.mu.Lock()
	lnk, ok := p.links[pid]
	delete(p.links, pid)
	p.mu.Unlock()

	if ok {
		lnk.Close()
	}
}
