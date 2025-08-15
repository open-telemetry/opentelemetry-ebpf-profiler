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

func TestGoLabels(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	r := &testutils.MockReporter{}
	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.Labels)
	traceCh, _ := testutils.StartTracer(context.Background(), t, enabledTracers, r, false)
	for _, tc := range [][]string{
		{"./golbls_1_23.test", "123"},
		{"./golbls_1_24.test", "124"},
		{"./golbls_cgo.test", "cgo"},
	} {
		t.Run(tc[0], func(t *testing.T) {
			// Use a separate exe for getting labels as the bpf code doesn't seem to work with
			// go test static binaries at the moment, not clear if that's a problem with the bpf
			// code or a bug/fact of life for static go binaries and getting g from TLS.
			cookie := tc[1]
			cmd := exec.Command(tc[0], "-subtest", cookie)
			err := cmd.Start()
			require.NoError(t, err)

			for trace := range traceCh {
				if trace == nil {
					continue
				}
				if len(trace.CustomLabels) > 0 {
					hits := 0
					for k, v := range trace.CustomLabels {
						switch k {
						case "l1" + cookie:
							require.Len(t, v, 22)
							require.True(t, strings.HasPrefix(v, "label1"))
							hits++
						case "l2" + cookie:
							require.Len(t, v, 30)
							require.True(t, strings.HasPrefix(v, "label2"))
							hits++
						case "l3" + cookie:
							require.Len(t, v, 47)
							require.True(t, strings.HasPrefix(v, "label3"))
							hits++
						}
					}
					if hits == 3 {
						break
					}
				}
			}
			_ = cmd.Process.Signal(os.Kill)
			_ = cmd.Wait()
		})
	}
}
