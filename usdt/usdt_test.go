// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/util"
)

// Note: attach/scanMapping/Reconcile/Detach require a live process, a real ELF
// with .note.stapsdt, and kernel uprobe support, so they are exercised by the
// QEMU integration-test matrix rather than here. These unit tests cover the
// pure logic and lifecycle helpers.

func TestProbeKindFromName(t *testing.T) {
	for _, tt := range []struct {
		name string
		want ProbeKind
	}{
		{"alloc", ProbeHeapAlloc},
		{"free", ProbeHeapFree},
		{"mmap", ProbeUnknown},
		{"", ProbeUnknown},
		{"Alloc", ProbeUnknown}, // case-sensitive
	} {
		assert.Equal(t, tt.want, probeKindFromName(tt.name), "probeKindFromName(%q)", tt.name)
	}
}

func TestInstance_NumAttachedAndHasProbeKind(t *testing.T) {
	inst := &Instance{
		pid: 1,
		attached: map[ProbeKey]AttachedProbe{
			{PID: 1, Kind: ProbeHeapAlloc, Offset: 0x10}: {},
			{PID: 1, Kind: ProbeHeapFree, Offset: 0x20}:  {},
		},
	}

	assert.Equal(t, 2, inst.NumAttached())
	assert.True(t, inst.HasProbeKind(ProbeHeapAlloc))
	assert.True(t, inst.HasProbeKind(ProbeHeapFree))
	assert.False(t, inst.HasProbeKind(ProbeUnknown))

	// A nil instance must be safe: ProcessManager keeps *Instance values that
	// may be nil, and queries them without a nil check.
	var nilInst *Instance
	assert.Equal(t, 0, nilInst.NumAttached())
	assert.False(t, nilInst.HasProbeKind(ProbeHeapAlloc))
}

func TestNewManager(t *testing.T) {
	// Empty progs disables USDT support: (nil, nil), no error.
	m, err := NewManager(nil)
	require.NoError(t, err)
	assert.Nil(t, m)

	// A nil program for a requested kind is a configuration error.
	_, err = NewManager(map[ProbeKind]*cebpf.Program{ProbeHeapAlloc: nil})
	assert.Error(t, err)
}

func TestManager_Close(t *testing.T) {
	// A nil Manager is safe to close; ProcessManager.Close relies on this
	// when USDT support is disabled.
	var m *Manager
	assert.NoError(t, m.Close())

	// Close purges the parse cache.
	pc, err := lru.NewSynced[util.OnDiskFileIdentifier, []parsedProbe](
		8, util.OnDiskFileIdentifier.Hash32)
	require.NoError(t, err)
	pc.Add(util.OnDiskFileIdentifier{InodeNum: 1}, nil)
	require.Equal(t, 1, pc.Len())

	m2 := &Manager{parseCache: pc}
	require.NoError(t, m2.Close())
	assert.Equal(t, 0, pc.Len(), "Close purges the parse cache")
}
