// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms

import (
	"cmp"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"

	"github.com/elastic/go-perf"
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

func TestSnapshotResolveAddressGenerationValidity(t *testing.T) {
	oldLoadModuleMetadata := loadModuleMetadata
	loadModuleMetadata = func(_ *Module, _ string, _ int64) bool { return true }
	t.Cleanup(func() {
		loadModuleMetadata = oldLoadModuleMetadata
	})

	s := &Symbolizer{
		bpf: &bpfSymbolizer{},
	}

	const (
		moduleAddr = libpf.Address(0xffffffffc03cc610)
		bpfAddr    = moduleAddr + 1
	)

	err := s.updateSymbolsFrom(strings.NewReader(`ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb6000000 T _etext
ffffffffc03cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc03cc770 t perf_trace_xfs_perag_class	[xfs]`))
	require.NoError(t, err)

	setBPFSymbols(s.bpf, []bpfSymbol{
		{address: bpfAddr, size: 512, name: "bpf_prog_test"},
	})

	snap1 := s.Snapshot()
	moduleResolution, ok := snap1.ResolveAddress(moduleAddr)
	require.True(t, ok)
	assert.Equal(t, SymbolSourceModule, moduleResolution.Source)
	require.NotNil(t, moduleResolution.Module)
	assert.Equal(t, "xfs", moduleResolution.Module.Name())
	assert.True(t, snap1.IsGenerationValid(moduleResolution.Generation))

	bpfResolution, ok := snap1.ResolveAddress(bpfAddr)
	require.True(t, ok)
	assert.Equal(t, SymbolSourceBPF, bpfResolution.Source)
	assert.Equal(t, "bpf_prog_test", bpfResolution.BPFName)
	assert.Equal(t, uint(0), bpfResolution.BPFOffset)
	assert.True(t, snap1.IsGenerationValid(bpfResolution.Generation))

	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  uint64(bpfAddr),
		Name:  "bpf_prog_test",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	snap2 := s.Snapshot()
	assert.False(t, snap2.IsGenerationValid(bpfResolution.Generation))
	assert.True(t, snap2.IsGenerationValid(moduleResolution.Generation))

	err = s.updateSymbolsFrom(strings.NewReader(`ffffffffb5000000 T _text
ffffffffb5000123 T startup_64
ffffffffb6000000 T _etext
ffffffffc13cc610 t perf_trace_xfs_attr_list_class	[xfs]
ffffffffc13cc770 t perf_trace_xfs_perag_class	[xfs]`))
	require.NoError(t, err)

	snap3 := s.Snapshot()
	assert.False(t, snap3.IsGenerationValid(moduleResolution.Generation))
}

// setBPFSymbols stores the given symbols in the bpfSymbolizer as a sorted
// bpfSymbolTable. This replaces the production loadBPFPrograms for tests.
func setBPFSymbols(s *bpfSymbolizer, symbols []bpfSymbol) {
	sorted := make([]bpfSymbol, len(symbols))
	copy(sorted, symbols)
	slices.SortFunc(sorted, func(a, b bpfSymbol) int {
		return cmp.Compare(a.address, b.address)
	})
	s.table.Store(&bpfSymbolTable{
		generation: makeBPFGeneration(1),
		symbols:    sorted,
	})
}

// assertBPFSymbol checks that the BPF symbolizer resolves addr to the expected
// function name and offset.
func assertBPFSymbol(t *testing.T, s *Symbolizer, addr libpf.Address, eFuncName string, eOffset uint) {
	t.Helper()
	funcName, off, ok := s.Snapshot().LookupBPFSymbol(addr)
	if assert.True(t, ok, "expected BPF symbol at 0x%x", addr) {
		assert.Equal(t, eFuncName, funcName)
		assert.Equal(t, eOffset, off)
	}
}

// assertNoBPFSymbol checks that the BPF symbolizer does not resolve addr.
func assertNoBPFSymbol(t *testing.T, s *Symbolizer, addr libpf.Address) {
	t.Helper()
	_, _, ok := s.Snapshot().LookupBPFSymbol(addr)
	assert.False(t, ok, "expected no BPF symbol at 0x%x", addr)
}

func TestBPFUpdates(t *testing.T) {
	s := &Symbolizer{
		bpf: &bpfSymbolizer{},
	}

	bpfSymbols := []bpfSymbol{
		{address: 0xffffffc080f26228, size: 512, name: "bpf_prog_00354c172d366337_sd_devices"},
		{address: 0xffffffc080f26430, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f264d8, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f28490, size: 512, name: "bpf_prog_56551fa66be1356a_sd_devices"},
		{address: 0xffffffc080f2867c, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f2871c, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f2da64, size: 512, name: "bpf_prog_00354c172d366337_sd_devices"},
		{address: 0xffffffc080f304a0, size: 512, name: "bpf_prog_5be112cdf63b0d8c_sysctl_monitor"},
		{address: 0xffffffc080f3089c, size: 512, name: "bpf_prog_292e0637857c1257_cut_last"},
		{address: 0xffffffc080f3096c, size: 512, name: "bpf_prog_a97c143260cd9940_sd_devices"},
		{address: 0xffffffc080f32f4c, size: 512, name: "bpf_prog_79c5319176ee7ce5_sd_devices"},
		{address: 0xffffffc080f331e4, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f33288, size: 512, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f35f1c, size: 512, name: "bpf_prog_461f9f5162fd8042_sd_devices"},
		{address: 0xffffffc080f3629c, size: 512, name: "bpf_prog_b8f4fb5f08605bc5"},
	}

	setBPFSymbols(s.bpf, bpfSymbols)

	// Adding a symbol at the end with a known size of 12288 bytes. This ensures
	// that an address 10240 bytes into the symbol is covered even though that
	// far exceeds a single page past the symbol start.
	const lastSymAddr = libpf.Address(0xffffffc080f38288)
	const lastSymSize = uint32(12288)
	err := s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: uint64(lastSymAddr),
		Len:  lastSymSize,
		Name: "bpf_prog_05cbe5ca7b74dd09_sys_enter",
	})
	require.NoError(t, err)

	// exact symbol match
	assertBPFSymbol(t, s, lastSymAddr, "bpf_prog_05cbe5ca7b74dd09_sys_enter", 0)

	// 10240 bytes into the last symbol must resolve correctly
	assertBPFSymbol(t, s, lastSymAddr+10240, "bpf_prog_05cbe5ca7b74dd09_sys_enter", 10240)

	// address beyond the symbol's end must not resolve
	assertNoBPFSymbol(t, s, lastSymAddr+libpf.Address(lastSymSize))

	// remove the added symbol
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  uint64(lastSymAddr),
		Name:  "bpf_prog_05cbe5ca7b74dd09_sys_enter",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// the address goes poof
	assertNoBPFSymbol(t, s, lastSymAddr)

	// add it back
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: uint64(lastSymAddr),
		Len:  lastSymSize,
		Name: "bpf_prog_05cbe5ca7b74dd09_sys_enter",
	})
	require.NoError(t, err)

	// find a pre-existing symbol by aiming slightly above its start
	assertBPFSymbol(t, s, 0xffffffc080f3089e, "bpf_prog_292e0637857c1257_cut_last", 0x2)

	// remove the pre-existing symbol
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  0xffffffc080f3089c,
		Name:  "bpf_prog_292e0637857c1257_cut_last",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// the address no longer resolves (previous symbol ends before 0x3089e)
	assertNoBPFSymbol(t, s, 0xffffffc080f3089e)

	// put the removed symbol back
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f3089c,
		Len:  512,
		Name: "bpf_prog_292e0637857c1257_cut_last",
	})
	require.NoError(t, err)

	// and it's right there where we put it
	assertBPFSymbol(t, s, 0xffffffc080f3089e, "bpf_prog_292e0637857c1257_cut_last", 0x2)

	// checking for lost symbols triggering full reload
	err = s.bpf.handleBPFUpdate(nil)
	assert.NotNil(t, err)

	// trampolines and non-bpf_prog_ symbols are silently ignored
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f26226,
		Name: "bpf_trampoline_6442536467",
	})
	require.NoError(t, err)
	assertNoBPFSymbol(t, s, 0xffffffc080f26226)

	// a bpf_prog_ symbol added before existing ones is found correctly
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f26000,
		Len:  512,
		Name: "bpf_prog_earliest",
	})
	require.NoError(t, err)
	assertBPFSymbol(t, s, 0xffffffc080f26000, "bpf_prog_earliest", 0)

	// removing it works
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  0xffffffc080f26000,
		Name:  "bpf_prog_earliest",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)
	assertNoBPFSymbol(t, s, 0xffffffc080f26000)
}

func TestBPFSnapshotGenerations(t *testing.T) {
	s := &Symbolizer{
		bpf: &bpfSymbolizer{},
	}

	const addr = libpf.Address(0xffffffc080f26228)
	setBPFSymbols(s.bpf, []bpfSymbol{
		{address: addr, size: 512, name: "bpf_prog_00354c172d366337_sd_devices"},
	})

	snap1 := s.Snapshot()
	require.NotNil(t, snap1.bpf)
	bpfGen1 := snap1.bpf.generation
	assert.Equal(t, makeBPFGeneration(1), bpfGen1)
	assertBPFSymbol(t, s, addr, "bpf_prog_00354c172d366337_sd_devices", 0)

	err := s.bpf.handleBPFUpdate(nil)
	assert.Error(t, err)
	snapAfterLost := s.Snapshot()
	require.NotNil(t, snapAfterLost.bpf)
	assert.Equal(t, bpfGen1, snapAfterLost.bpf.generation)

	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  uint64(addr),
		Name:  "bpf_prog_00354c172d366337_sd_devices",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	snap2 := s.Snapshot()
	require.NotNil(t, snap2.bpf)
	assert.Equal(t, makeBPFGeneration(2), snap2.bpf.generation)
	assertNoBPFSymbol(t, s, addr)

	funcName, off, ok := snap1.LookupBPFSymbol(addr)
	require.True(t, ok)
	assert.Equal(t, "bpf_prog_00354c172d366337_sd_devices", funcName)
	assert.Equal(t, uint(0), off)
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
