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
package luajit

import (
	"debug/elf"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type prefixKey struct {
	pid libpf.PID
	pfx lpm.Prefix
}

// ebpfMapsMockup implements the ebpf interface as test mockup
type ebpfMapsMockup struct {
	prefixes map[prefixKey]lpm.Prefix
}

var _ interpreter.EbpfHandler = &ebpfMapsMockup{}

func (m *ebpfMapsMockup) CoredumpTest() bool {
	return false
}

func (m *ebpfMapsMockup) UpdatePidInterpreterMapping(pid libpf.PID,
	pfx lpm.Prefix, _ uint8, _ host.FileID, _ uint64) error {
	m.prefixes[prefixKey{pid: pid, pfx: pfx}] = pfx
	return nil
}

func (m *ebpfMapsMockup) DeletePidInterpreterMapping(pid libpf.PID, pfx lpm.Prefix) error {
	delete(m.prefixes, prefixKey{pid: pid, pfx: pfx})
	return nil
}

func (m *ebpfMapsMockup) UpdateInterpreterOffsets(uint16, host.FileID,
	[]util.Range) error {
	return nil
}

func (m *ebpfMapsMockup) UpdateProcData(libpf.InterpreterType, libpf.PID,
	unsafe.Pointer) error {
	return nil
}

func (m *ebpfMapsMockup) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

// TestSynchronizeMappings tests that if a mapping is realloc'd we do the right thing.
func TestSynchronizeMappings(t *testing.T) {
	for _, tc := range []struct {
		calls []process.Mapping
	}{
		{[]process.Mapping{
			{Vaddr: 0x2000, Length: 0x1000, Flags: elf.PF_X},
			{Vaddr: 0x1000, Length: 0x2000, Flags: elf.PF_X},
		}},
		{[]process.Mapping{
			{Vaddr: 0x2000, Length: 0x1000, Flags: elf.PF_X},
			{Vaddr: 0x2000, Length: 0x2000, Flags: elf.PF_X},
		}},
	} {
		ebpf := &ebpfMapsMockup{prefixes: make(map[prefixKey]lpm.Prefix)}
		lj := &luajitInstance{
			jitRegions:  make(regionMap),
			prefixes:    make(map[regionKey][]lpm.Prefix),
			prefixesByG: make(map[libpf.Address][]lpm.Prefix),
		}
		for _, call := range tc.calls {
			err := lj.synchronizeMappings(ebpf, 0, []process.Mapping{call})
			require.NoError(t, err)
		}
		initial := tc.calls[0]
		require.Empty(t, lj.jitRegions[initial])
		require.Empty(t, lj.prefixes[regionKey{initial.Vaddr, initial.Vaddr + initial.Length}])
		final := tc.calls[len(tc.calls)-1]
		require.NotEmpty(t, lj.jitRegions[final])
		require.NotEmpty(t, lj.prefixes[regionKey{final.Vaddr, final.Vaddr + final.Length}])
		err := lj.Detach(ebpf, 0)
		require.NoError(t, err)
		require.Empty(t, ebpf.prefixes)
	}
}
