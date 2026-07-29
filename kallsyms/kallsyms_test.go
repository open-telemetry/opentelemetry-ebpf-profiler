// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertSymbol(t *testing.T, s *Symbolizer, pc libpf.Address,
	eModName, eFuncName string, eOffset uint) {
	kmod, err := s.Snapshot().GetModuleByAddress(pc)
	if assert.NoError(t, err) && assert.Equal(t, kmod.Name(), eModName) {
		funcName, offset, err := kmod.LookupSymbolByAddress(pc)
		if assert.NoError(t, err) {
			assert.Equal(t, eFuncName, funcName)
			assert.Equal(t, eOffset, offset)
		}
	}
}

// TestNewSymbolizerCustomRootFs verifies that NewSymbolizer reads kallsyms
// from path.Join(rootFs, "proc", "kallsyms") rather than the hardcoded path.
func TestNewSymbolizerCustomRootFs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "proc"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "proc", "kallsyms"),
		[]byte(`ffffffffb5000000 T _stext
ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb6000000 T _etext
`),
		0o644,
	))

	s, err := NewSymbolizer(dir)
	require.NoError(t, err)
	require.NotNil(t, s)

	assertSymbol(t, s, 0xffffffffb5000123, Kernel, "startup_64", 0)
}

func TestKallSyms(t *testing.T) {
	// override the metadata loading to avoid mixing data from running system
	oldLoadModuleMetadata := loadModuleMetadata
	loadModuleMetadata = func(_ *Module, _ string, _ int64) bool { return true }
	t.Cleanup(func() {
		loadModuleMetadata = oldLoadModuleMetadata
	})

	s := &Symbolizer{}

	err := s.updateSymbolsFrom(strings.NewReader(`0000000000000000 t pvh_start_xen
0000000000000000 T _stext
0000000000000000 T _text
0000000000000000 T startup_64
0000000000000000 T __pfx___startup_64
0000000000000000 T _etext`))
	assert.Equal(t, ErrSymbolPermissions, err)

	err = s.updateSymbolsFrom(strings.NewReader(`0000000000000000 A __per_cpu_start
0000000000001000 A cpu_debug_store
0000000000002000 A irq_stack_backing_store
ffffffffb5000000 t pvh_start_xen
ffffffffb5000000 T _stext
ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb5000180 T __pfx___startup_64
ffffffffb5000190 T __startup_64
ffffffffb5000460 T __pfx_startup_64_setup_gdt_idt
ffffffffb5000470 T startup_64_setup_gdt_idt
ffffffffb5001000 T __pfx___traceiter_initcall_level
ffffffffb6000000 T _etext
ffffffffc03cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc03cc770 t perf_trace_xfs_perag_class	[xfs]
ffffffffc03cc8b0 t perf_trace_xfs_inodegc_worker	[xfs]
ffffffffc03cc9d0 t perf_trace_xfs_fs_class	[xfs]
ffffffffc03ccb20 t perf_trace_xfs_inodegc_shrinker_scan	[xfs]`))
	require.NoError(t, err)

	snap := s.Snapshot()
	_, err = snap.GetModuleByName("foo")
	assert.Equal(t, err, ErrNoModule)

	_, err = snap.GetModuleByAddress(0x1010)
	assert.Equal(t, err, ErrNoModule)

	_, err = snap.GetModuleByAddress(0xffffffffffff0000)
	assert.Equal(t, err, ErrNoModule)

	assertSymbol(t, s, 0xffffffffb5000470, Kernel, "startup_64_setup_gdt_idt", 0)
	assertSymbol(t, s, 0xffffffffc03cc610, "xfs", "perf_trace_xfs_attr_list_class", 0)
	assertSymbol(t, s, 0xffffffffc03cc610+1, "xfs", "perf_trace_xfs_attr_list_class", 1)

	err = s.updateSymbolsFrom(strings.NewReader(`0000000000000000 A __per_cpu_start
0000000000001000 A cpu_debug_store
0000000000002000 A irq_stack_backing_store
ffffffffb5000000 t pvh_start_xen
ffffffffb5000000 T _stext
ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb5000180 T __pfx___startup_64
ffffffffb5000190 T __startup_64
ffffffffb5000460 T __pfx_startup_64_setup_gdt_idt
ffffffffb5000470 T startup_64_setup_gdt_idt
ffffffffb5001000 T __pfx___traceiter_initcall_level
ffffffffb6000000 T _etext
ffffffffc13cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc13cc770 t perf_trace_xfs_perag_class	[xfs]
ffffffffc13cc8b0 t perf_trace_xfs_inodegc_worker	[xfs]
ffffffffc13cc9d0 t perf_trace_xfs_fs_class	[xfs]
ffffffffc13ccb20 t perf_trace_xfs_inodegc_shrinker_scan	[xfs]
ffffffffc1400000 t foo	[foo]
ffffffffc13fcb20 t init_xfs_fs	[xfs]`))
	require.NoError(t, err)

	snap = s.Snapshot()
	_, err = snap.GetModuleByAddress(0xffffffffc03cc610 + 1)
	assert.Equal(t, ErrNoModule, err)

	_, err = snap.GetModuleByAddress(0xffffffffc13fcb20)
	assert.Equal(t, ErrNoModule, err)

	assertSymbol(t, s, 0xffffffffb5000470, "vmlinux", "startup_64_setup_gdt_idt", 0)
	assertSymbol(t, s, 0xffffffffc13cc610+1, "xfs", "perf_trace_xfs_attr_list_class", 1)
}

func TestModuleSnapshotGenerations(t *testing.T) {
	oldLoadModuleMetadata := loadModuleMetadata
	loadModuleMetadata = func(_ *Module, _ string, _ int64) bool { return true }
	t.Cleanup(func() {
		loadModuleMetadata = oldLoadModuleMetadata
	})

	s := &Symbolizer{}

	err := s.updateSymbolsFrom(strings.NewReader(`ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb6000000 T _etext
ffffffffc03cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc03cc770 t perf_trace_xfs_perag_class	[xfs]`))
	require.NoError(t, err)

	snap1 := s.Snapshot()
	require.NotNil(t, snap1.modules)
	assert.Equal(t, makeModuleGeneration(1), snap1.modules.generation)
	kmod, err := snap1.GetModuleByAddress(0xffffffffc03cc610)
	require.NoError(t, err)
	assert.Equal(t, "xfs", kmod.Name())

	err = s.updateSymbolsFrom(strings.NewReader(`ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb6000000 T _etext
ffffffffc13cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc13cc770 t perf_trace_xfs_perag_class	[xfs]`))
	require.NoError(t, err)

	snap2 := s.Snapshot()
	require.NotNil(t, snap2.modules)
	assert.Equal(t, makeModuleGeneration(2), snap2.modules.generation)

	kmod, err = snap1.GetModuleByAddress(0xffffffffc03cc610)
	require.NoError(t, err)
	assert.Equal(t, "xfs", kmod.Name())

	_, err = snap2.GetModuleByAddress(0xffffffffc03cc610)
	assert.ErrorIs(t, err, ErrNoModule)
	kmod, err = snap2.GetModuleByAddress(0xffffffffc13cc610)
	require.NoError(t, err)
	assert.Equal(t, "xfs", kmod.Name())
}

func BenchmarkSort(b *testing.B) {
	r := strings.NewReader(`0000000000000000 A __per_cpu_start
0000000000001000 A cpu_debug_store
0000000000002000 A irq_stack_backing_store
ffffffffb5000000 t pvh_start_xen
ffffffffb5000000 T _stext
ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb5000180 T __pfx___startup_64
ffffffffb5000190 T __startup_64
ffffffffb5000460 T __pfx_startup_64_setup_gdt_idt
ffffffffb5000470 T startup_64_setup_gdt_idt
ffffffffb5001000 T __pfx___traceiter_initcall_level
ffffffffb6000000 T _etext
ffffffffc13cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc13cc770 t perf_trace_xfs_perag_class	[xfs]
ffffffffc13cc8b0 t perf_trace_xfs_inodegc_worker	[xfs]
ffffffffc13cc9d0 t perf_trace_xfs_fs_class	[xfs]
ffffffffc13ccb20 t perf_trace_xfs_inodegc_shrinker_scan	[xfs]
ffffffffc1400000 t foo	[foo]
ffffffffc13fcb20 t init_xfs_fs	[xfs]`)

	s := &Symbolizer{}

	for b.Loop() {
		r.Seek(0, io.SeekStart)
		if err := s.updateSymbolsFrom(r); err != nil {
			b.Fail()
		}
	}

}
