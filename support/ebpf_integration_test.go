//go:build integration && linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package support

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/elastic/otel-profiling-agent/libpf/rlimit"
)

// TestEbpf is a simplified version of otel-profiling-agent.
// It takes the same eBPF ELF file (from support/ebpf/tracer.ebpf.x86)
// and loads it into the kernel. With this test, we can make sure,
// our eBPF code is loaded correctly and not rejected by the kernel.
// As this tests uses the BPF syscall, it is protected by the build tag integration.
func TestEbpf(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		t.Fatalf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	var coll *cebpf.CollectionSpec
	t.Run("Load Tracer specification", func(t *testing.T) {
		coll, err = LoadCollectionSpec()
		if err != nil {
			t.Fatalf("Failed to load specification for tracer: %v", err)
		}
	})

	var tracepointProbe *cebpf.Program
	t.Run("Load tracepoint probe", func(t *testing.T) {
		tracepointProbe, err = cebpf.NewProgram(coll.Programs["tracepoint__sys_enter_read"])
		if err != nil {
			t.Fatalf("Failed to load tracepoint probe: %v", err)
		}
	})

	var hook link.Link
	t.Run("Attach probe to tracepoint", func(t *testing.T) {
		hook, err = link.Tracepoint("syscalls", "sys_enter_read", tracepointProbe, nil)
		if err != nil {
			t.Fatalf("Failed to hook tracepoint probe: %v", err)
		}
	})

	t.Run("Remove tracepoint hook", func(t *testing.T) {
		if err := hook.Close(); err != nil {
			t.Fatalf("Failed to remove tracepoint hook: %v", err)
		}
	})

	t.Run("Unload tracepoint probe", func(t *testing.T) {
		if err := tracepointProbe.Close(); err != nil {
			t.Fatalf("Failed to unload tracepoint probe: %v", err)
		}
	})
}
