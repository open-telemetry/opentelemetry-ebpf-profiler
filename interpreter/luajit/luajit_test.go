// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

// Run
func TestIntegration(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}
	// TODO:
	// can we make sure the native function above main is the right openresty function?
	// can we make sure the native function at the leaf are right (ie for pcre)?
	for _, tc := range []struct {
		resource  string
		structure []string
	}{
		{"fib", []string{
			"main",
			"u:run_duration",
			"f",
			"fib:calc",
			"Fibonacci:naive",
			"inner",
		}},
		{"comp", []string{
			"main",
			"u:run_duration",
			"f",
			"c:comp",
			"compress_file",
			"lzw:compress",
		}},
		// TODO: get the unwinding working across ffi callbacks.
		// {"ffi", []string{
		// 	"main",
		// 	"u:run_duration",
		// 	"f",
		// 	"q:sort",
		// 	"ffi:C:qsort",
		// }},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			for _, tag := range []string{
				"1.17.8.2-alpine",
				"1.19.9.1-alpine",
				"1.21.4.3-buster",
				"1.25.3.2-bullseye",
				"jammy",
				"alpine",
			} {
				t.Run(tag, func(t *testing.T) {
					image := "openresty/openresty:" + tag
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)

					defer cancel()

					cont := startContainer(ctx, t, image)

					h, err := cont.Host(ctx)
					require.NoError(t, err)

					port, err := cont.MappedPort(ctx, "80")
					require.NoError(t, err)

					var waitGroup sync.WaitGroup
					defer waitGroup.Wait()
					makeRequests(ctx, t, &waitGroup, tc.resource, h, port)

					r := &mockReporter{symbols: make(symbolMap)}
					traceCh, trc := startTracer(ctx, t, r)

					passes, fails, traces := 0, 0, 0
				done:
					for {
						select {
						case <-ctx.Done():
							break done
						case trace := <-traceCh:
							st, err := cont.State(ctx)
							require.NoError(t, err)
							// See if PID is openresty
							if int(trace.PID) != st.Pid {
								continue
							}
							traces++
							if validateTrace(t, trc, trace, tc.structure, r) {
								passes++
							} else {
								fails++
							}
							if passes > 10 {
								break done
							}
						}
					}

					t.Cleanup(func() {
						ctx, canc := context.WithTimeout(context.Background(), time.Second)
						defer canc()

						err := cont.Terminate(ctx)
						if err != nil {
							require.ErrorIs(t, err, context.DeadlineExceeded)
						}
					})

					t.Log("passes", passes, "fails", fails, "total", traces)
					cancel()
				})
			}
		})
	}
}

// Find lua traces and test that they are good
func validateTrace(t *testing.T, trc *tracer.Tracer, trace *host.Trace,
	st []string, r *mockReporter) bool {
	if trace.Frames[len(trace.Frames)-1].Type == libpf.AbortFrame {
		// It happens, a lot look fine, should probably investigate...
		return false
	}

	// Finally convert it to flex all the proto parsing/remote code
	ct := trc.TraceProcessor().ConvertTrace(trace)
	require.NotNil(t, ct)

	cleanFrames := removeSentinel(trace.Frames)

	// Lua sentinel frame should be removed.  If we hit any remote memory
	// issues some error frames get created and removeSentinel will remove
	// them as well so just ignore any that don't have length alignment.
	if len(cleanFrames) != len(ct.Files) {
		return false
	}

	return validateFrames(t, cleanFrames, st, ct, r)
}

func validateFrames(t *testing.T, cleanFrames []host.Frame, st []string,
	ct *libpf.Trace, r *mockReporter) bool {
	j := len(cleanFrames) - 1
outer:
	for _, s := range st {
		if s[0] == '@' {
			a, err := strconv.ParseInt(s[1:], 16, 64)
			require.NoError(t, err)
			addr := libpf.AddressOrLineno(uint64(a))
			for ; j >= 0; j-- {
				if cleanFrames[j].Type == libpf.NativeFrame {
					if cleanFrames[j].Lineno == addr {
						continue outer
					}
				}
			}
		} else {
			for ; j >= 0; j-- {
				symKey := luaKey{ct.Files[j], uint32(cleanFrames[j].Lineno)}
				luaSym, ok := r.symbols[symKey]
				if ok {
					if luaSym.functionName == s {
						continue outer
					}
				}
			}
		}
		return false
	}
	return true
}

func startTracer(ctx context.Context, t *testing.T, r *mockReporter) (chan *host.Trace,
	*tracer.Tracer) {
	enabledTracers, _ := tracertypes.Parse("luajit")
	enabledTracers.Enable(tracertypes.LuaJITTracer)
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:               r,
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		FilterErrorFrames:      false,
		SamplesPerSecond:       9999,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
	})
	require.NoError(t, err)

	// Initial scan of /proc filesystem to list currently active PIDs and have them processed.
	err = trc.StartPIDEventProcessor(ctx)
	require.NoError(t, err)

	// Attach our tracer to the perf event
	err = trc.AttachTracer()
	require.NoError(t, err)

	log.Info("Attached tracer program")

	err = trc.EnableProfiling()
	require.NoError(t, err)

	err = trc.AttachSchedMonitor()
	require.NoError(t, err)

	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	log.Printf("Attached sched monitor")

	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	err = trc.StartMapMonitors(ctx, traceCh)
	require.NoError(t, err)

	return traceCh, trc
}

func startContainer(ctx context.Context, t *testing.T, image string) testcontainers.Container {
	t.Log("starting", image)
	// The offset tests load both platform images so docker gets confused if we don't specify
	var platform string
	switch runtime.GOARCH {
	case "arm64":
		platform = "linux/arm64"
	case "amd64":
		platform = "linux/amd64"
	default:
		panic("bad architecture")
	}
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"80"},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      "./testdata/nginx.conf",
					ContainerFilePath: "/usr/local/openresty/nginx/conf/nginx.conf",
				},
				{
					HostFilePath:      "./testdata/lua",
					ContainerFilePath: "/usr/local/openresty/nginx/lua",
				},
			},
			ImagePlatform: platform,
			WaitingFor:    wait.ForHTTP("/"),
		},
		Started: true,
	})
	require.NoError(t, err)
	return cont
}

func makeRequests(ctx context.Context, t *testing.T, wg *sync.WaitGroup,
	res, h string, p nat.Port) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			url := "http://" + net.JoinHostPort(h, p.Port()) + "/" + res
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				t.Log(err)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				t.Log(err)
				continue
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Log(err)
			}
			showContents := false
			if showContents {
				t.Log(string(body))
			}
		}
	}()
}

type mockIntervals struct{}

func (f mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (f mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (f mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type luaKey struct {
	fileID libpf.FileID
	pc     uint32
}

type luaSym struct {
	functionName string
}

type symbolMap map[luaKey]luaSym

type mockReporter struct {
	symbols symbolMap
}

func (f mockReporter) ExecutableMetadata(*reporter.ExecutableMetadataArgs) {}

func (f mockReporter) FrameKnown(_ libpf.FrameID) bool {
	return true
}
func (f mockReporter) FrameMetadata(*reporter.FrameMetadataArgs) {}

func isRoot() bool {
	return os.Geteuid() == 0
}

func removeSentinel(frames []host.Frame) []host.Frame {
	for i, f := range frames {
		if f.File == 0 {
			return append(frames[:i], frames[i+1:]...)
		}
	}
	return frames
}
