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
	"go.opentelemetry.io/ebpf-profiler/interpreter/luajit"
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
	// repeat tests with jit on/off
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
			// FIXME: somethings wrong with the unwinder here where we never get compress_file
			// AND lzw:compress but only one or the other.
			// "lzw:compress",
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

					t.Cleanup(func() {
						ctx2, canc := context.WithTimeout(context.Background(), time.Second)
						defer canc()

						err := cont.Terminate(ctx2)
						if err != nil {
							require.ErrorIs(t, err, context.DeadlineExceeded)
						}
					})

					h, err := cont.Host(ctx)
					require.NoError(t, err)

					port, err := cont.MappedPort(ctx, "8080")
					require.NoError(t, err)

					r := &mockReporter{symbols: make(symbolMap)}
					traceCh, trc := startTracer(ctx, t, r)

					var waitGroup sync.WaitGroup
					defer waitGroup.Wait()
					makeRequests(ctx, t, &waitGroup, tc.resource, h, port)

					st, err := cont.State(ctx)
					require.NoError(t, err)

					passes, fails, traces := 0, 0, 0
					tick := time.NewTicker(5 * time.Second)
				done:
					for {
						select {
						case <-tick.C:
							t.Log("passes", passes, "fails", fails, "total", traces)
						case <-ctx.Done():
							break done
						case trace := <-traceCh:
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
							if passes > 1 {
								break done
							}
						}
					}

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
	// Finally convert it to flex all the proto parsing/remote code
	ct, err := trc.TraceProcessor().ConvertTrace(trace)
	require.NotNil(t, ct)
	require.NoError(t, err)

	return validateFrames(t, removeSentinel(trace.Frames), st, r)
}

func validateFrames(t *testing.T, frames []host.Frame, st []string,
	r *mockReporter) bool {
	j := len(frames) - 1
outer:
	for _, s := range st {
		if s[0] == '@' {
			a, err := strconv.ParseInt(s[1:], 16, 64)
			require.NoError(t, err)
			addr := libpf.AddressOrLineno(uint64(a))
			for ; j >= 0; j-- {
				if frames[j].Type == libpf.NativeFrame {
					if frames[j].Lineno == addr {
						continue outer
					}
				}
			}
		} else {
			for ; j >= 0; j-- {
				frameID := luajit.CreateFrameID(&frames[j])
				sym := r.getFunctionName(frameID)
				if sym == s {
					continue outer
				}
			}
		}
		return false
	}
	return true
}

// FIXME: refactor this to copy less code.
func startTracer(ctx context.Context, t *testing.T, r *mockReporter) (chan *host.Trace,
	*tracer.Tracer) {
	enabledTracers, _ := tracertypes.Parse("luajit")
	enabledTracers.Enable(tracertypes.LuaJITTracer)
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		DebugTracer:            true,
		Reporter:               r,
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		SamplesPerSecond:       1000,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
	})
	require.NoError(t, err)

	trc.StartPIDEventProcessor(ctx)

	err = trc.AttachTracer()
	require.NoError(t, err)

	log.Info("Attached tracer program")

	err = trc.EnableProfiling()
	require.NoError(t, err)

	err = trc.AttachSchedMonitor()
	require.NoError(t, err)

	traceCh := make(chan *host.Trace)

	// Spawn monitors for the various result maps
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
			ExposedPorts: []string{"8080"},
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
	numRequests := 0
	tick := time.NewTicker(5 * time.Second)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tick.C:
				t.Log("requests: ", numRequests)
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
			numRequests++
		}
	}()
}

type mockIntervals struct{}

func (f mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (f mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (f mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type symbolMap map[libpf.FrameID]string

type mockReporter struct {
	mu      sync.Mutex
	symbols symbolMap
}

var _ reporter.SymbolReporter = &mockReporter{}

func (m *mockReporter) ExecutableMetadata(*reporter.ExecutableMetadataArgs) {
}
func (m *mockReporter) FrameKnown(_ libpf.FrameID) bool { return false }
func (m *mockReporter) ExecutableKnown(libpf.FileID) bool {
	return false
}
func (m *mockReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.symbols[args.FrameID] = args.FunctionName
}

func (m *mockReporter) getFunctionName(frameID libpf.FrameID) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.symbols[frameID]
}

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
