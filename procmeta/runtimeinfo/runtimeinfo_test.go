// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimeinfo_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/procmeta/runtimeinfo"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// fakeInstance is an interpreter.Instance reporting a fixed runtime.
type fakeInstance struct {
	interpreter.InstanceStubs
	name, version string
	// reports is false for an interpreter that cannot tell its runtime, as one whose
	// version data is unread does.
	reports bool
}

func (i *fakeInstance) RuntimeInfo() (string, string, bool) {
	return i.name, i.version, i.reports
}

func (i *fakeInstance) Detach(interpreter.EbpfHandler, libpf.PID) error { return nil }

func runtime(name, version string) *fakeInstance {
	return &fakeInstance{name: name, version: version, reports: true}
}

func oid(inode uint64) util.OnDiskFileIdentifier {
	return util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: inode}
}

// fakeProcess reports nothing but its executable's identity and its PID, all the
// enricher asks of it. The embedded interface is nil, so any other call panics.
type fakeProcess struct {
	process.Process
	exe util.OnDiskFileIdentifier
	// err is returned instead of exe, as it is for a process whose executable
	// cannot be stat'ed any more.
	err error
}

func (p *fakeProcess) GetExecutableFileIdentifier() (util.OnDiskFileIdentifier, error) {
	return p.exe, p.err
}

func (*fakeProcess) PID() libpf.PID { return 1 }

var errNotImplemented = errors.New("not implemented")

// executable returns a process whose executable has the given identity.
func executable(exe util.OnDiskFileIdentifier) *fakeProcess {
	return &fakeProcess{exe: exe}
}

// enrich runs the enricher once and returns the attributes it contributed.
func enrich(t *testing.T, req *procmeta.ResourceRequest) (map[string]string, bool) {
	t.Helper()
	res, changed := runtimeinfo.NewEnricher().EnrichResource(req)
	if res == nil {
		return nil, changed
	}
	attrs := make(map[string]string, res.Attributes().Len())
	res.Attributes().Range(func(k string, v pcommon.Value) bool {
		attrs[k] = v.Str()
		return true
	})
	return attrs, changed
}

func TestEnricher_SelectRuntime(t *testing.T) {
	exeOID := oid(1)
	libOID := oid(2)

	tests := map[string]struct {
		interpreters map[util.OnDiskFileIdentifier]interpreter.Instance
		proc         *fakeProcess
		expected     map[string]string
	}{
		"no interpreter attached": {
			proc: executable(exeOID),
		},
		"single runtime in the executable": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("cpython", "3.11.4"),
			},
			proc: executable(exeOID),
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"single runtime in a library": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				libOID: runtime("cpython", "3.11.4"),
			},
			proc: executable(exeOID),
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"executable wins over embedded runtime": {
			// A Go binary embedding CPython must report Go.
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("go", "1.24.6"),
				libOID: runtime("cpython", "3.11.4"),
			},
			proc: executable(exeOID),
			expected: map[string]string{
				"process.runtime.name":    "go",
				"process.runtime.version": "1.24.6",
			},
		},
		"executable reports nothing, fall back to a library": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &fakeInstance{},
				libOID: runtime("ruby", "3.3.0"),
			},
			proc: executable(exeOID),
			expected: map[string]string{
				"process.runtime.name":    "ruby",
				"process.runtime.version": "3.3.0",
			},
		},
		"executable not observed, several libraries": {
			// Deterministic despite Go's randomized map iteration: smallest
			// (name, version) wins, so samples do not split across resources.
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				oid(2): runtime("ruby", "3.3.0"),
				oid(3): runtime("cpython", "3.12.7"),
				oid(4): runtime("cpython", "3.11.4"),
				oid(5): runtime("php", "8.3.1"),
			},
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"executable cannot be identified, fall back to a library": {
			// The exe symlink is gone, as it is for a process that exited under us.
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("go", "1.24.6"),
				libOID: runtime("cpython", "3.11.4"),
			},
			proc: &fakeProcess{err: errNotImplemented},
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"no interpreter reports a runtime": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &fakeInstance{},
				libOID: &fakeInstance{},
			},
			proc: executable(exeOID),
		},
		"version omitted when unknown": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("erlang", ""),
			},
			proc: executable(exeOID),
			expected: map[string]string{
				"process.runtime.name": "erlang",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var state any
			proc := test.proc
			if proc == nil {
				proc = executable(util.OnDiskFileIdentifier{})
			}
			attrs, changed := enrich(t, &procmeta.ResourceRequest{
				Process:      proc,
				Interpreters: test.interpreters,
				State:        &state,
			})
			require.Equal(t, test.expected, attrs)
			require.Equal(t, test.expected != nil, changed)
		})
	}
}

// TestEnricher_ResolvesOnceUntilExec verifies that the runtime is resolved as soon as
// an interpreter attaches, then left alone — re-resolving would let it flip as more
// attach — and resolved afresh after an exec.
func TestEnricher_ResolvesOnceUntilExec(t *testing.T) {
	e := runtimeinfo.NewEnricher()
	exeOID := oid(1)
	var state any

	// No interpreter attached yet: nothing to report, but keep looking.
	req := &procmeta.ResourceRequest{Process: executable(exeOID), State: &state}
	_, changed := e.EnrichResource(req)
	require.False(t, changed)
	require.Nil(t, state)

	// An interpreter attaches.
	req.Interpreters = map[util.OnDiskFileIdentifier]interpreter.Instance{
		exeOID: runtime("cpython", "3.11.4"),
	}
	res, changed := e.EnrichResource(req)
	require.True(t, changed)
	v, ok := res.Attributes().Get("process.runtime.version")
	require.True(t, ok)
	require.Equal(t, "3.11.4", v.Str())

	// Already resolved: a second interpreter does not change what is reported.
	req.Interpreters[oid(2)] = runtime("cpython", "3.9.1")
	_, changed = e.EnrichResource(req)
	require.False(t, changed)

	// An exec replaces the program, so the runtime resolves again. The manager
	// performs one by clearing the state slot and the contribution before calling any
	// enricher, so this one has nothing of its own to do about it.
	state = nil
	req.Interpreters = map[util.OnDiskFileIdentifier]interpreter.Instance{
		exeOID: runtime("ruby", "3.3.0"),
	}
	res, changed = e.EnrichResource(req)
	require.True(t, changed)
	v, ok = res.Attributes().Get("process.runtime.name")
	require.True(t, ok)
	require.Equal(t, "ruby", v.Str())

	// An exec into a program hosting no runtime reports nothing, which cannot mean
	// "the previous runtime still holds": the manager already dropped it.
	state = nil
	req.Interpreters = nil
	_, changed = e.EnrichResource(req)
	require.False(t, changed)
	require.Nil(t, state)
}

func TestEnricher_ResourceConfig(t *testing.T) {
	// The runtime is derived from the interpreters the process manager passes in,
	// so this enricher needs no mappings of its own.
	cfg := runtimeinfo.NewEnricher().ResourceConfig()
	require.Nil(t, cfg.WantMapping)
}
