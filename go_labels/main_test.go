// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

func TestGoCustomLabels(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &testutils.MockReporter{}
	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.GoLabels)
	traceCh, _ := testutils.StartTracer(ctx, t, enabledTracers, r)

	// Use a separate exe for getting labels as the bpf code doesn't seem to work with
	// go test static binaries at the moment, not clear if that's a problem with the bpf
	// code or a bug/fact of life for static go binaries and getting g from TLS.
	cmd := exec.Command("./go_labels_canary.test")
	err := cmd.Start()
	require.NoError(t, err)

	// Wait 1 second for traces to arrive.
	for trace := range traceCh {
		if trace == nil {
			continue
		}
		if len(trace.CustomLabels) > 0 {
			for k, v := range trace.CustomLabels {
				t.Logf("Custom label: %s=%s", k, v)
			}
			break
		}
	}
	cancel()
	_ = cmd.Process.Signal(os.Kill)
	_ = cmd.Wait()
}
