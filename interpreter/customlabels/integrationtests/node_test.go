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

package customlabels_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"

	"time"

	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type symbolMap map[libpf.FrameID]string

const N_WORKERS int = 8

var files = []string{
	"AUTHORS.md",
	"CODE_OF_CONDUCT.md",
	"CONTRIBUTING.md",
	"INDEX.md",
	"PUBLISHING.md",
	"USING_ADVANCED.md",
	"USING_PRO.md",
	"broken.md",
}

func TestIntegration(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	for _, nodeVersion := range []string{
		// As of today, node:latest is v24.6.0
		// Eventually, it will be something where the offsets have changed,
		// and start failing. At that point, update the list of offsets
		// so this passes, and also add a test for the latest v24 if latest
		// is on v25 by then.
		"latest",
		"22.18.0",
		"20.19.4",
	} {
		name := "node-" + nodeVersion
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			defer cancel()

			cont := startContainer(ctx, t, nodeVersion)

			enabledTracers, err := tracertypes.Parse("labels,v8")
			require.NoError(t, err)

			r := &mockReporter{symbols: make(symbolMap)}
			traceCh, trc := testutils.StartTracer(ctx, t, enabledTracers, r, false)

			testHTTPEndpoint(ctx, t, cont)
			framesPerWorkerId := make(map[int]int)
			framesPerFileName := make(map[string]int)

			totalWorkloadFrames := 0
			unlabeledWorkloadFrames := 0

			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()

			for {
				select {
				case <-timer.C:
					goto done
				case trace := <-traceCh:
					if trace == nil {
						continue
					}
					ct, err := trc.TraceProcessor().ConvertTrace(trace)
					require.NotNil(t, ct)
					require.NoError(t, err)
					workerId, okWid := trace.CustomLabels["workerId"]
					filePath, okFname := trace.CustomLabels["filePath"]
					var fileName string
					if okFname {
						fileName = path.Base(filePath)
					}
					knownWorkloadFrames := []string{
						"lex",
						"parse",
						"blockTokens",
						"readFile",
						"readFileHandle",
					}
					hasWorkloadFrame := false
					for i := range ct.FrameTypes {
						if ct.FrameTypes[i] == libpf.V8Frame {
							id := libpf.NewFrameID(ct.Files[i], ct.Linenos[i])
							name := r.getFunctionName(id)
							if slices.Contains(knownWorkloadFrames, name) {
								hasWorkloadFrame = true
							}
						}
					}

					if hasWorkloadFrame {
						totalWorkloadFrames++
						if !(okWid && okFname) {
							unlabeledWorkloadFrames++
						}
					}

					if okWid {
						val, err := strconv.Atoi(workerId)
						require.NoError(t, err)

						require.GreaterOrEqual(t, val, 0)
						require.Less(t, val, N_WORKERS)

						framesPerWorkerId[val]++
					}

					if okFname {
						require.Contains(t, files, fileName)
						framesPerFileName[fileName]++
					}
				}
			}
		done:
			totalWidFrames := 0
			// for 8 workers, each should have roughly 1/8
			// of the labeled frames. There will be a bit of skew,
			// so accept anything above 60% of that.
			for i := 0; i < N_WORKERS; i++ {
				totalWidFrames += framesPerWorkerId[i]
			}
			expectedWorkerAvg := float64(totalWidFrames) / float64(N_WORKERS)
			for i := 0; i < N_WORKERS; i++ {
				require.Less(t, expectedWorkerAvg*0.60, float64(framesPerWorkerId[i]))
			}
			// Each of the documents should account for some nontrivial amount of time,
			// but since they aren't all the same length, we are less strict.
			totalFnameFrames := 0
			for _, v := range framesPerFileName {
				totalFnameFrames += v
			}
			expectedFnameAvg := float64(totalFnameFrames) / float64(len(framesPerFileName))
			for _, v := range framesPerFileName {
				require.Less(t, expectedFnameAvg*0.2, float64(v))
			}

			// Really, there should be zero frames in the
			// `marked` workload that aren't under labels,
			// but accept a 1% slop because the unwinder
			// isn't perfect (e.g. it might interrupt the
			// process when the Node environment is in an
			// undefined state)
			require.Less(t, 100*unlabeledWorkloadFrames, totalWorkloadFrames)
		})
	}
}

func startContainer(ctx context.Context, t *testing.T,
	nodeVersion string) testcontainers.Container {
	t.Log("starting container for node version", nodeVersion)
	//nolint:dogsled
	_, path, _, _ := runtime.Caller(0)
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: filepath.Dir(path) + "/testdata/node-md-render/",
				BuildArgs: map[string]*string{
					"NODE_VERSION": &nodeVersion,
				},
			},
			ExposedPorts: []string{"80/tcp"},
			WaitingFor:   wait.ForHTTP("/docs/AUTHORS.md"),
		},
		Started: true,
	})
	require.NoError(t, err)
	return cont
}

func testHTTPEndpoint(ctx context.Context, t *testing.T, cont testcontainers.Container) {
	const numGoroutines = 10
	const requestsPerGoroutine = 10000

	host, err := cont.Host(ctx)
	require.NoError(t, err)

	port, err := cont.MappedPort(ctx, "80")
	require.NoError(t, err)

	baseURL := "http://" + net.JoinHostPort(host, port.Port())

	var wg sync.WaitGroup

	var errs []error
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		errs = append(errs, nil)
		go func() {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				//nolint:gosec
				file := files[rand.Intn(len(files))]

				url := fmt.Sprintf("%s/docs/%s", baseURL, file)

				//nolint:gosec
				resp, err := http.Get(url)
				if err != nil {
					errs[i] = err
					return
				}

				// if we don't read body to completion, the http library will kill the connection
				// instead of reusing it, and we might run out of ports.
				_, err = io.ReadAll(resp.Body)
				if err != nil {
					errs[i] = err
					return
				}

				err = resp.Body.Close()
				if err != nil {
					errs[i] = err
					return
				}

				if http.StatusOK != resp.StatusCode {
					errs[i] = fmt.Errorf("Expected status 200 for %s", file)
					return
				}
			}
		}()
	}

	wg.Wait()
	require.NoError(t, errors.Join(errs...))
}

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
