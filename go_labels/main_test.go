// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

func TestGoCustomLabels(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	r := &testutils.MockReporter{}
	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.GoLabels)
	traceCh, _ := testutils.StartTracer(context.Background(), t, enabledTracers, r)
	for _, tc := range []string{
		"./go_labels_canary1.23.test",
		"./go_labels_canary1.24.test",
	} {
		t.Run(tc, func(t *testing.T) {
			// Use a separate exe for getting labels as the bpf code doesn't seem to work with
			// go test static binaries at the moment, not clear if that's a problem with the bpf
			// code or a bug/fact of life for static go binaries and getting g from TLS.
			cmd := exec.Command(tc)
			err := cmd.Start()
			require.NoError(t, err)

			for trace := range traceCh {
				if trace == nil {
					continue
				}
				if len(trace.CustomLabels) > 0 {
					for k, v := range trace.CustomLabels {
						switch k {
						case "l1":
							require.Len(t, v, 22)
							require.True(t, strings.HasPrefix(v, "label1"))
						case "l2":
							require.Len(t, v, 30)
							require.True(t, strings.HasPrefix(v, "label2"))
						case "l3":
							require.Len(t, v, 47)
							require.True(t, strings.HasPrefix(v, "label3"))
						default:
							t.Fail()
						}
					}
					break
				}
			}
			_ = cmd.Process.Signal(os.Kill)
			_ = cmd.Wait()
		})
	}
}
