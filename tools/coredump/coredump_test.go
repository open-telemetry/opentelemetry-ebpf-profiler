// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

func TestCoreDumps(t *testing.T) {
	cases, err := findTestCases(true)
	require.NoError(t, err)
	require.NotEmpty(t, cases)

	cloudClient, err := cloudstore.Client()
	require.NoError(t, err)
	store, err := modulestore.New(cloudClient,
		cloudstore.PublicReadURL(), cloudstore.ModulestoreS3Bucket(), "modulecache")
	require.NoError(t, err)

	for _, filename := range cases {
		t.Run(filename, func(t *testing.T) {
			testCase, err := readTestCase(filename)
			require.NoError(t, err)
			if testCase.Skip != "" {
				t.Skip(testCase.Skip)
			}

			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			require.NoError(t, err)
			defer core.Close()

			data, err := ExtractTraces(t.Context(), core, false, nil)

			require.NoError(t, err)
			require.Equal(t, testCase.Threads, data)
		})
	}
}

// faultingReaderAt wraps an io.ReaderAt and returns an error for reads
// matching a predicate. This simulates bpf_probe_read_user failures where
// the kernel cannot read a page that is swapped out.
type faultingReaderAt struct {
	inner       io.ReaderAt
	shouldFault func(off int64, size int) bool
}

func (f *faultingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if f.shouldFault != nil && f.shouldFault(off, len(p)) {
		return 0, fmt.Errorf("injected fault at offset 0x%x (size %d)", off, len(p))
	}
	return f.inner.ReadAt(p, off)
}

// faultingProcess wraps a process.Process and overrides GetRemoteMemory to
// return a RemoteMemory backed by a faultingReaderAt. This is passed as the
// eBPF process to ExtractTraces so that bpf_probe_read_user hits injected
// faults, while the interpreter manager uses the real process and can still
// read the code objects successfully.
type faultingProcess struct {
	process.Process
	faultingRM remotememory.RemoteMemory
}

func newFaultingProcess(pr process.Process, shouldFault func(off int64, size int) bool) *faultingProcess {
	rm := pr.GetRemoteMemory()
	return &faultingProcess{
		Process: pr,
		faultingRM: remotememory.RemoteMemory{
			ReaderAt: &faultingReaderAt{
				inner:       rm.ReaderAt,
				shouldFault: shouldFault,
			},
			Bias: rm.Bias,
		},
	}
}

func (fp *faultingProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return fp.faultingRM
}

func (fp *faultingProcess) OpenELF(path string) (*pfelf.File, error) {
	return fp.Process.(pfelf.ELFOpener).OpenELF(path)
}

// TestPythonRecoverCodeObject tests that Python frames are recovered correctly
// when the eBPF bpf_probe_read_user fails to read a PyCodeObject (e.g. because
// the page was swapped out). The agent-side code should still read the code
// object via the coredump memory (simulating process_vm_readv which supports
// page faults) and produce the same symbolized output.
func TestPythonRecoverCodeObject(t *testing.T) {
	cases, err := findTestCases(true)
	require.NoError(t, err)

	var pythonCases []string
	for _, c := range cases {
		base := filepath.Base(c)
		if !strings.HasPrefix(base, "python") {
			continue
		}
		tc, err := readTestCase(c)
		if err != nil || tc.Skip != "" {
			continue
		}
		pythonCases = append(pythonCases, c)
	}
	require.NotEmpty(t, pythonCases, "no Python test cases found")

	cloudClient, err := cloudstore.Client()
	require.NoError(t, err)
	store, err := modulestore.New(cloudClient,
		cloudstore.PublicReadURL(), cloudstore.ModulestoreS3Bucket(), "modulecache")
	require.NoError(t, err)

	for _, filename := range pythonCases {
		t.Run(filename+"/recover", func(t *testing.T) {
			testCase, err := readTestCase(filename)
			require.NoError(t, err)

			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			require.NoError(t, err)
			defer core.Close()

			// Wrap the process with a faulting reader that fails all
			// PyCodeObject-sized reads. Pass it as the eBPF process
			// so bpf_probe_read_user faults, while the real process
			// is used by the interpreter manager for recovery reads.
			faulting := newFaultingProcess(core, func(_ int64, size int) bool {
				return size == pyCodeObjectBPFReadSize
			})

			data, err := ExtractTraces(t.Context(), core, false, nil, faulting)
			require.NoError(t, err)
			require.Equal(t, testCase.Threads, data)
		})
	}
}
