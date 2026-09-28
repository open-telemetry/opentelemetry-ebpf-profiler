package tracer

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// As RewriteMaps() was deprecated in cilium/ebpf we do not
// want to export this function and make it part of the public
// API of tracer, so make it available just for testing.
var RewriteMaps = rewriteMaps

// SynchronizeProcessForTest prepares a process for unwinding in integration tests.
func (t *Tracer) SynchronizeProcessForTest(pid, tid libpf.PID) {
	t.processManager.SynchronizeProcess(process.New(pid, tid))
}
