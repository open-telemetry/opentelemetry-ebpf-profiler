// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (mockReporter) ExecutableKnown(_ libpf.FileID) bool                   { return true }
func (mockReporter) ExecutableMetadata(_ *reporter.ExecutableMetadataArgs) {}

func isRoot() bool {
	return os.Geteuid() == 0
}

func TestGoLabels(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}
	ctx := context.Background()

	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.Labels)

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:               &mockReporter{},
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        uint32(math.MaxUint32 / 100),
		VerboseMode:            true,
	})
	require.NoError(t, err)

	trc.StartPIDEventProcessor(ctx)

	err = trc.AttachTracer()
	require.NoError(t, err)

	t.Log("Attached tracer program")

	err = trc.EnableProfiling()
	require.NoError(t, err)

	err = trc.AttachSchedMonitor()
	require.NoError(t, err)

	traceCh := make(chan *host.Trace)

	err = trc.StartMapMonitors(ctx, traceCh)
	require.NoError(t, err)

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
