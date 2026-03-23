// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
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
	name := schedProcessFreeHookName(libpf.MapKeysToSet(t.ebpfProgs))
	return t.attachToTracepoint("sched", "sched_process_free", t.ebpfProgs[name])
}

// AttachPrctlMonitor attaches a tracepoint on prctl() to detect when a process
// names an anonymous VMA "OTEL_CTX" via prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...).
// This triggers a PID resynchronization so the profiler can discover newly published
// process context mappings.
func (t *Tracer) AttachPrctlMonitor() error {
	prog, ok := t.ebpfProgs["tracepoint__sys_enter_prctl"]
	if !ok {
		return fmt.Errorf("eBPF program tracepoint__sys_enter_prctl not found")
	}
	return t.attachToTracepoint("syscalls", "sys_enter_prctl", prog)
}
