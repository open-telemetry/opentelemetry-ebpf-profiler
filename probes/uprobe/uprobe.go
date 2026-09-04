// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package uprobe implements a per-process probe that attaches a PID-filtered uprobe
// to every process that maps a given target executable or shared library.
//
// An OTel config using this approach could look like this:
//
//	receivers:
//	  ebpf_profiler:
//	    probes:
//	      - uprobe/malloc
//
//	extensions:
//	  uprobe/malloc:
//	    target: /usr/lib/x86_64-linux-gnu/libc.so.6
//	    symbol: malloc
package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const progName = "kprobe__generic"

type Config struct {
	Target string `mapstructure:"target"`
	Symbol string `mapstructure:"symbol"`
}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	if c.Target == "" {
		return fmt.Errorf("uprobe: missing target")
	}
	if c.Symbol == "" {
		return fmt.Errorf("uprobe: missing symbol")
	}
	return nil
}

type probe struct {
	target string
	symbol string

	// prog is the shared eBPF program loaded once in Load, reused across Attach calls.
	prog *cebpf.Program

	mu       sync.Mutex
	unloaded bool
	links    map[libpf.PID][]link.Link
}

func (p *probe) String() string {
	return "uprobe " + p.target + ":" + p.symbol
}

func New(cfg Config) (tracer.Probe, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &probe{
		target: cfg.Target,
		symbol: cfg.Symbol,
		links:  make(map[libpf.PID][]link.Link),
	}, nil
}

// Load implements tracer.Probe. It loads the shared eBPF program once and registers
// the probe as a per-process attacher so that SynchronizeProcess drives per-PID
// attachment rather than a single system-wide link.
func (p *probe) Load(_ context.Context, reg tracer.ProbeRegistrar, probeCtx *tracer.ProbeContext) error {
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
	p.prog = prog

	// Register for per-process callbacks instead of a global link.
	probeCtx.AddAttacher(p)
	return nil
}

// Match implements processmanager.ProbeAttacher.
func (p *probe) Match(_ process.Process, mapping *process.RawMapping) bool {
	return mapping.Path == p.target ||
		filepath.Base(mapping.Path) == filepath.Base(p.target)
}

// Attach implements processmanager.ProbeAttacher. Opens a PID-restricted uprobe
// for the given process and stores the link for later cleanup.
func (p *probe) Attach(pr process.Process, mapping *process.RawMapping) error {
	pid := pr.PID()
	mappingFile, err := pr.OpenMappingFile(mapping)
	if err != nil {
		return fmt.Errorf("%s: open mapping %s: %w", p, mapping.Path, err)
	}
	defer mappingFile.Close()

	fdFile, ok := mappingFile.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("%s: mapping %s has no file descriptor", p, mapping.Path)
	}
	mappingPath := fmt.Sprintf("/proc/self/fd/%d", fdFile.Fd())

	ex, err := link.OpenExecutable(mappingPath)
	if err != nil {
		return fmt.Errorf("%s: open mapping %s: %w", p, mapping.Path, err)
	}

	lnk, err := ex.Uprobe(p.symbol, p.prog, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		return fmt.Errorf("%s: attach to PID %d: %w", p, pid, err)
	}

	p.mu.Lock()
	if p.unloaded {
		p.mu.Unlock()
		// closing link due to unloaded probe
		return lnk.Close()
	}
	p.links[pid] = append(p.links[pid], lnk)
	p.mu.Unlock()
	return nil
}

// Detach implements processmanager.ProbeAttacher. Closes all uprobe links
// for the exiting process.
func (p *probe) Detach(pid libpf.PID) {
	p.mu.Lock()
	links := p.links[pid]
	delete(p.links, pid)
	p.mu.Unlock()

	for _, lnk := range links {
		lnk.Close()
	}
}

func (p *probe) Unload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unloaded = true
	var unloadErrs error
	for pid, pidLinks := range p.links {
		for _, lnk := range pidLinks {
			unloadErrs = errors.Join(unloadErrs, lnk.Close())
		}
		delete(p.links, pid)
	}

	return unloadErrs
}
