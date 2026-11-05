// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

type recordingProbeAttacher struct {
	matchedMapping  *process.RawMapping
	attachedMapping *process.RawMapping
	attachedFileID  libpf.FileID
	attachedELFRef  *pfelf.Reference
}

func (a *recordingProbeAttacher) Match(_ process.Process, mapping *process.RawMapping) bool {
	a.matchedMapping = mapping
	return true
}

func (a *recordingProbeAttacher) Attach(_ process.Process, mapping *process.RawMapping,
	fileID libpf.FileID, elfRef *pfelf.Reference,
) error {
	a.attachedMapping = mapping
	a.attachedFileID = fileID
	a.attachedELFRef = elfRef
	return nil
}

func (*recordingProbeAttacher) Detach(libpf.PID) {}

// TestAttachProbesForMappingForwardsMatchedMapping verifies that Attach receives
// the exact mapping accepted by Match. Per-mapping probes need this to resolve
// symbol offsets and attach against the same backing ELF.
func TestAttachProbesForMappingForwardsMatchedMapping(t *testing.T) {
	attacher := &recordingProbeAttacher{}
	pm := &ProcessManager{
		probeAttachers: []ProbeAttacher{attacher},
		attachedProbes: make(map[libpf.PID]map[ProbeAttacher]libpf.Void),
	}
	pr := &testProcess{pid: 123}
	mapping := &process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x2000,
		Path:   "/usr/lib/libc.so.6",
	}

	fileID := libpf.NewFileID(1, 2)
	elfRef := pfelf.NewReference(mapping.Path, pr)
	pm.attachProbesForMapping(pr, mapping, fileID, elfRef)

	require.Same(t, attacher.matchedMapping, attacher.attachedMapping)
	require.Equal(t, fileID, attacher.attachedFileID)
	require.Same(t, elfRef, attacher.attachedELFRef)
	require.Contains(t, pm.attachedProbes[pr.pid], attacher)
}
