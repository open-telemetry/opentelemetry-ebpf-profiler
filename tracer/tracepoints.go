/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/elastic/otel-profiling-agent/rlimit"
)

// attachToTracepoint attaches an eBPF program of type tracepoint to a tracepoint in the kernel
// defined by group and name.
// Otherwise it returns an error.
func (t *Tracer) attachToTracepoint(group, name string, prog *ebpf.Program) error {
	hp := hookPoint{
		group: group,
		name:  name,
	}
	hook, err := link.Tracepoint(hp.group, hp.name, prog, nil)
	if err != nil {
		return fmt.Errorf("failed to configure tracepoint on %#v: %v", hp, err)
	}
	t.hooks[hp] = hook
	return nil
}

// AttachSchedMonitor attaches a kprobe to the process scheduler. This hook detects the
// exit of a process and enables us to clean up data we associated with this process.
func (t *Tracer) AttachSchedMonitor() error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	prog := t.ebpfProgs["tracepoint__sched_process_exit"]
	return t.attachToTracepoint("sched", "sched_process_exit", prog)
}
