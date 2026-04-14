// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// ReporterMetadata is a type alias for samples.ProbeOriginMetadata.
type ReporterMetadata = samples.ProbeOriginMetadata

// TracerMaps exposes loaded eBPF and maps for reuse.
type TracerMaps map[string]*cebpf.Map

// Probe defines the interface that allows custom stack unwinding
// trigger points.
type Probe interface {
	// Load attaches a probe that triggers stack unwinding.
	// Returns the link and a reference to self to keep the probe alive.
	Load(libpf.Origin, TracerMaps, *SystemVariables) (link.Link, error)

	// ReportMetadata provides the necessary metadata to report
	// the events of the Probe.
	ReportMetadata() ReporterMetadata
}

func (t *Tracer) Enable(p Probe) error {
	originID := libpf.Origin(t.probeOriginsCount.Load() + 1)
	lnk, err := p.Load(originID, t.ebpfMaps, t.systemVars)
	if err != nil {
		return err
	}

	// Register the probe with the reporter if available
	if t.probeRegistrar != nil {
		if err := t.probeRegistrar.RegisterProbeOrigin(originID, p.ReportMetadata()); err != nil {
			lnk.Close()
			return err
		}
	} else {
		return fmt.Errorf("reporter not available to register probe")
	}

	// Update the tracer internal probe origins tracking
	t.probeOriginsCount.Add(1)
	t.hooks = append(t.hooks, lnk)

	return nil
}

// CollectionSpecWith returns a CollectionSpec optimized for the necessary elements.
func CollectionSpecWith(extraMaps []string, extraProgs []string, extraVars []string, systemVars *SystemVariables) (*cebpf.CollectionSpec, error) {
	orig, err := support.LoadCollectionSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load specification for tracers: %v", err)
	}

	coll := &cebpf.CollectionSpec{
		Maps:      make(map[string]*cebpf.MapSpec),
		Programs:  make(map[string]*cebpf.ProgramSpec),
		Variables: make(map[string]*cebpf.VariableSpec),
	}

	// Prepare new coll:
	// Copy required maps
	mapsToCopy := append([]string{".rodata.var"}, extraMaps...)
	for _, name := range mapsToCopy {
		coll.Maps[name] = orig.Maps[name].Copy()
	}

	// Copy required programs
	for _, name := range extraProgs {
		coll.Programs[name] = orig.Programs[name].Copy()
	}

	// Copy required variables
	varsToCopy := append([]string{
		"inverse_pac_mask",
		"tpbase_offset",
		"task_stack_offset",
		"stack_ptregs_offset",
	}, extraVars...)
	for _, name := range varsToCopy {
		coll.Variables[name] = orig.Variables[name].Copy()
	}

	// Set necessary values in new coll
	if err := setSystemVariables(coll, systemVars.TPBaseOffset,
		systemVars.TaskStackOffset, systemVars.StackPtregsOffset); err != nil {
		return nil, err
	}

	return coll, nil
}
