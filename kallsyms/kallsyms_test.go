// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms

import (
	"io"
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
	kmod, err := s.GetModuleByAddress(pc)
	if assert.NoError(t, err) && assert.Equal(t, kmod.Name(), eModName) {
		funcName, offset, err := kmod.LookupSymbolByAddress(pc)
		if assert.NoError(t, err) {
			assert.Equal(t, eFuncName, funcName)
			assert.Equal(t, eOffset, offset)
		}
	}
}

func TestKallSyms(t *testing.T) {
	// override the metadata loading to avoid mixing data from running system
	loadModuleMetadata = func(_ *Module, _ string, _ int64) bool { return true }

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

	_, err = s.GetModuleByName("foo")
	assert.Equal(t, err, ErrNoModule)

	_, err = s.GetModuleByAddress(0x1010)
	assert.Equal(t, err, ErrNoModule)

	_, err = s.GetModuleByAddress(0xffffffffffff0000)
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

	_, err = s.GetModuleByAddress(0xffffffffc03cc610 + 1)
	assert.Equal(t, ErrNoModule, err)

	_, err = s.GetModuleByAddress(0xffffffffc13fcb20)
	assert.Equal(t, ErrNoModule, err)

	assertSymbol(t, s, 0xffffffffb5000470, "vmlinux", "startup_64_setup_gdt_idt", 0)
	assertSymbol(t, s, 0xffffffffc13cc610+1, "xfs", "perf_trace_xfs_attr_list_class", 1)
}

// setBPFSymbols builds a bpf Module from the given symbols and stores it
// in the bpfSymbolizer. This replaces the production loadBPFPrograms for tests.
func setBPFSymbols(s *bpfSymbolizer, symbols []bpfSymbol) {
	if len(symbols) == 0 {
		s.module.Store(nil)
		return
	}

	minAddr := symbols[0].address
	for _, sym := range symbols[1:] {
		if sym.address < minAddr {
			minAddr = sym.address
		}
	}

	mod := &Module{
		start: minAddr,
	}
	mod.addName("bpf")

	sizes := make(map[libpf.Address]uint32)
	for _, sym := range symbols {
		mod.symbols = append(mod.symbols, symbol{
			offset: uint32(sym.address - mod.start),
			index:  mod.addName(sym.name),
		})
		sizes[sym.address] = sym.size
	}

	s.sizes = sizes
	s.finish(mod)
	s.module.Store(mod)
}

func TestBPFUpdates(t *testing.T) {
	loadModuleMetadata = func(_ *Module, _ string, _ int64) bool { return true }

	s := &Symbolizer{
		bpf: &bpfSymbolizer{},
	}

	// Initialize the main symbolizer modules so GetModuleByAddress doesn't
	// panic when falling through the bpf module check.
	err := s.updateSymbolsFrom(strings.NewReader(
		"ffffffe4f3395268 t pci_host_common_probe        [pci_host_common]"))
	require.NoError(t, err)

	// no bpf symbols — handleBPFUpdate should fail on nil module
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f38288,
		Name: "bpf_prog_05cbe5ca7b74dd09_sys_enter",
	})
	assert.NotNil(t, err)

	bpfSymbols := []bpfSymbol{
		{address: 0xffffffc080f26228, size: 1024, name: "bpf_prog_00354c172d366337_sd_devices"},
		{address: 0xffffffc080f26430, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f264d8, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f28490, size: 1024, name: "bpf_prog_56551fa66be1356a_sd_devices"},
		{address: 0xffffffc080f2867c, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f2871c, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f2da64, size: 1024, name: "bpf_prog_00354c172d366337_sd_devices"},
		{address: 0xffffffc080f304a0, size: 1024, name: "bpf_prog_5be112cdf63b0d8c_sysctl_monitor"},
		{address: 0xffffffc080f3089c, size: 1024, name: "bpf_prog_292e0637857c1257_cut_last"},
		{address: 0xffffffc080f3096c, size: 1024, name: "bpf_prog_a97c143260cd9940_sd_devices"},
		{address: 0xffffffc080f32f4c, size: 1024, name: "bpf_prog_79c5319176ee7ce5_sd_devices"},
		{address: 0xffffffc080f331e4, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_egress"},
		{address: 0xffffffc080f33288, size: 1024, name: "bpf_prog_772db7720b2728e9_sd_fw_ingress"},
		{address: 0xffffffc080f35f1c, size: 1024, name: "bpf_prog_461f9f5162fd8042_sd_devices"},
		{address: 0xffffffc080f3629c, size: 1024, name: "bpf_prog_b8f4fb5f08605bc5"},
	}

	setBPFSymbols(s.bpf, bpfSymbols)

	// Adding a symbol at the end with a known size of 12288 bytes. This ensures
	// that an address 10240 bytes into the symbol is covered by the module even
	// though that far exceeds a single page past the symbol start.
	const lastSymAddr = libpf.Address(0xffffffc080f38288)
	const lastSymSize = uint32(12288)
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: uint64(lastSymAddr),
		Len:  lastSymSize,
		Name: "bpf_prog_05cbe5ca7b74dd09_sys_enter",
	})
	require.NoError(t, err)

	mod, err := s.GetModuleByName("bpf")
	require.NoError(t, err)

	// remember how long the names were (they should not grow due to reuse)
	max := len(mod.names)

	// exact module match
	mod, err = s.GetModuleByAddress(lastSymAddr)
	require.NoError(t, err)
	assert.Equal(t, "bpf", mod.Name())

	// 10240 bytes into the last symbol must still be within the module
	mod, err = s.GetModuleByAddress(lastSymAddr + 10240)
	require.NoError(t, err)
	assert.Equal(t, "bpf", mod.Name())

	// exact symbol match
	name, off, err := mod.LookupSymbolByAddress(lastSymAddr)
	require.NoError(t, err)
	assert.Equal(t, "bpf_prog_05cbe5ca7b74dd09_sys_enter", name)
	assert.Equal(t, uint(0x0), off)

	// 10240 bytes into the last symbol must resolve correctly
	name, off, err = mod.LookupSymbolByAddress(lastSymAddr + 10240)
	require.NoError(t, err)
	assert.Equal(t, "bpf_prog_05cbe5ca7b74dd09_sys_enter", name)
	assert.Equal(t, uint(10240), off)

	// remove the added symbol
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  uint64(lastSymAddr),
		Name:  "bpf_prog_05cbe5ca7b74dd09_sys_enter",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// the address goes poof
	_, err = s.GetModuleByAddress(lastSymAddr)
	assert.Equal(t, ErrNoModule, err)

	// add it back
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: uint64(lastSymAddr),
		Len:  lastSymSize,
		Name: "bpf_prog_05cbe5ca7b74dd09_sys_enter",
	})
	require.NoError(t, err)

	mod, err = s.GetModuleByName("bpf")
	require.NoError(t, err)

	// the names did not grow
	assert.Equal(t, max, len(mod.names))

	// find the pre-existing symbol by aiming slightly above
	mod, err = s.GetModuleByAddress(0xffffffc080f3089e)
	require.NoError(t, err)

	name, off, err = mod.LookupSymbolByAddress(0xffffffc080f3089e)
	require.NoError(t, err)
	assert.Equal(t, "bpf_prog_292e0637857c1257_cut_last", name)
	assert.Equal(t, uint(0x2), off)

	// remove the pre-existing symbol
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  0xffffffc080f3089c,
		Name:  "bpf_prog_292e0637857c1257_cut_last",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// look for it again
	mod, err = s.GetModuleByAddress(0xffffffc080f3089e)
	require.NoError(t, err)

	// the symbol just below is matching now
	name, off, err = mod.LookupSymbolByAddress(0xffffffc080f3089e)
	require.NoError(t, err)
	assert.Equal(t, "bpf_prog_5be112cdf63b0d8c_sysctl_monitor", name)
	assert.Equal(t, uint(0x3fe), off)

	// put the removed symbol back
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f3089c,
		Name: "bpf_prog_292e0637857c1257_cut_last",
	})
	require.NoError(t, err)

	mod, err = s.GetModuleByAddress(0xffffffc080f3089e)
	require.NoError(t, err)

	// and it's right there where we put it
	name, off, err = mod.LookupSymbolByAddress(0xffffffc080f3089e)
	require.NoError(t, err)
	assert.Equal(t, "bpf_prog_292e0637857c1257_cut_last", name)
	assert.Equal(t, uint(0x2), off)

	// still good with the name reuse
	mod, err = s.GetModuleByAddress(0xffffffc080f3089e)
	require.NoError(t, err)
	assert.Equal(t, max, len(mod.names))

	// checking for lost symbols triggering full reload
	err = s.bpf.handleBPFUpdate(nil)
	assert.NotNil(t, err)

	// adding before start shifts the module start
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr: 0xffffffc080f26226,
		Name: "add_before_start",
	})
	require.NoError(t, err)

	assertSymbol(t, s, 0xffffffc080f26226, "bpf", "add_before_start", 0)
	assertSymbol(t, s, 0xffffffc080f26228, "bpf", "bpf_prog_00354c172d366337_sd_devices", 0)

	// removing the first symbol shifts the module start forward
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  0xffffffc080f26226,
		Name:  "add_before_start",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// module start shifted back to the original first symbol
	assertSymbol(t, s, 0xffffffc080f26228, "bpf", "bpf_prog_00354c172d366337_sd_devices", 0)

	// removing the (new) first symbol also works
	err = s.bpf.handleBPFUpdate(&perf.KSymbolRecord{
		Addr:  0xffffffc080f26228,
		Name:  "bpf_prog_00354c172d366337_sd_devices",
		Flags: unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER,
	})
	require.NoError(t, err)

	// the next symbol is now the first
	assertSymbol(t, s, 0xffffffc080f26430, "bpf", "bpf_prog_772db7720b2728e9_sd_fw_egress", 0)
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
