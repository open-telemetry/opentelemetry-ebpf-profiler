//go:build host_integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Checks Resolve and Locate against the fixtures in testdata: Resolve against
// them as ELF, for the access model each was built to carry, and Locate against
// them running, where every fixture reports where its thread-locals live and
// the descriptor produced for them must resolve to the same address.

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"bufio"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// requireFixture names the target that builds the fixtures, which `make
// test-deps` does not: they need a musl toolchain and a host that can run them.
func requireFixture(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	require.NoErrorf(t, err, "run `make tlsvar-execs` from the repository root")
}

func openFixture(t *testing.T, name string) *pfelf.File {
	t.Helper()
	path := filepath.Join("testdata", name)
	requireFixture(t, path)
	ef, err := pfelf.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { ef.Close() })
	return ef
}

// symbolValue is what a model leaves for Locate when its relocation resolves
// the module alone.
func symbolValue(_ elf.Machine, sym *libpf.Symbol) uint64 {
	return uint64(sym.Address)
}

// symbollessDescAddend is what a symbol-less TLSDESC leaves for Locate, set by
// the descriptor shape the architecture emits: nothing on aarch64, which emits
// one per variable carrying that variable's offset as its addend, and the whole
// symbol offset on x86-64, which emits a single one for the module.
func symbollessDescAddend(machine elf.Machine, sym *libpf.Symbol) uint64 {
	if machine == elf.EM_X86_64 {
		return uint64(sym.Address)
	}
	return 0
}

func TestResolve(t *testing.T) {
	tests := map[string]struct {
		file       string
		wantAccess accessModel
		// wantAddend is what Resolve must leave for Locate to add, nil when
		// the loader resolves the offset in full.
		wantAddend func(elf.Machine, *libpf.Symbol) uint64
	}{
		"general-dynamic, desc dialect": {
			file: "libtlsvar_glibc_desc.so", wantAccess: accessTLSDesc,
		},
		"general-dynamic, GNU dialect": {
			file: "libtlsvar_glibc_gnu.so", wantAccess: accessGeneralDynamic,
		},
		"initial-exec": {
			file: "libtlsvar_glibc_ie.so", wantAccess: accessInitialExec,
		},
		"initial-exec, hidden symbol": {
			// Symbol-less, but the loader folds the addend into the GOT slot,
			// so Resolve leaves no addend of its own.
			file: "libtlsvar_glibc_ie_hidden.so", wantAccess: accessInitialExec,
		},
		"local-dynamic, GNU dialect": {
			file: "libtlsvar_glibc_ld.so", wantAccess: accessLocalDynamic, wantAddend: symbolValue,
		},
		"local-dynamic, desc dialect": {
			file: "libtlsvar_glibc_ld_desc.so", wantAccess: accessTLSDesc,
			wantAddend: symbollessDescAddend,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ef := openFixture(t, tc.file)
			sym := tlsSymbol(t, ef, "tls_var")

			v, err := Resolve(ef, sym)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAccess, v.access)
			// The relocation's own address, wherever the linker put the slot.
			assert.NotZero(t, v.elfAddr)
			var wantAddend uint64
			if tc.wantAddend != nil {
				wantAddend = tc.wantAddend(ef.Machine, sym)
			}
			assert.Equal(t, wantAddend, v.addend)
		})
	}
}

// The two hidden thread-locals of the ld_desc fixture share one symbol-less
// TLSDESC relocation on x86-64 and get one each on aarch64, so what tells them
// apart is the addend: which relocation it selects, and how much of the
// variable's offset it already carries.
func TestResolveSymbollessTLSDescByAddend(t *testing.T) {
	ef := openFixture(t, "libtlsvar_glibc_ld_desc.so")

	other := tlsSymbol(t, ef, "other_tls_var")
	tlsVar := tlsSymbol(t, ef, "tls_var")
	require.NotEqual(t, other.Address, tlsVar.Address)

	otherVar, err := Resolve(ef, other)
	require.NoError(t, err)
	tlsVarVar, err := Resolve(ef, tlsVar)
	require.NoError(t, err)

	// Same descriptor or not, the two must not resolve to one address.
	assert.NotEqual(t, otherVar, tlsVarVar)
	assert.Equal(t, symbollessDescAddend(ef.Machine, other), otherVar.addend)
	assert.Equal(t, symbollessDescAddend(ef.Machine, tlsVar), tlsVarVar.addend)
}

// A thread-local with no name is legal ELF, and the symbol-less relocations are
// what resolve it, since nothing can reference it by name. Resolving it must
// match resolving the same variable by name.
func TestResolveNamelessSymbol(t *testing.T) {
	ef := openFixture(t, "libtlsvar_glibc_ld_desc.so")
	named := tlsSymbol(t, ef, "tls_var")

	want, err := Resolve(ef, named)
	require.NoError(t, err)

	nameless := *named
	nameless.Name = ""
	got, err := Resolve(ef, &nameless)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestResolveLocalExec(t *testing.T) {
	ef := openFixture(t, "tlsvar_exe_glibc")
	sym := tlsSymbol(t, ef, "tls_var")

	v, err := Resolve(ef, sym)
	require.NoError(t, err)
	assert.Equal(t, accessLocalExec, v.access)
	assert.Zero(t, v.elfAddr)

	// The expected offsets below hold for this layout only, so fail loudly
	// rather than silently if a toolchain ever changes it.
	tlsProg := ef.ProgByType(elf.PT_TLS)
	require.NotNil(t, tlsProg)
	require.Equal(t, uint64(16), tlsProg.Memsz)
	require.Equal(t, uint64(8), tlsProg.Align)
	require.Equal(t, libpf.SymbolValue(8), sym.Address)

	var want int64
	switch ef.Machine {
	case elf.EM_AARCH64:
		// Variant I: past the 16-byte TCB/GAP_ABOVE_TP.
		want = 16 + 8
	case elf.EM_X86_64:
		// Variant II: the whole block sits below TP.
		want = 8 - 16
	default:
		t.Skipf("unsupported machine %s", ef.Machine)
	}
	assert.Equal(t, want, int64(v.addend))
}

// A thread-local defined but never referenced in a shared object has no access
// model: nothing relocates it, and only an executable gets a static TLS block.
func TestResolveUnsupported(t *testing.T) {
	ef := openFixture(t, "libtlsvar_glibc_noreloc.so")
	sym := tlsSymbol(t, ef, "tls_var")

	_, err := Resolve(ef, sym)
	require.ErrorIs(t, err, ErrUnsupportedModel)
}

// dynamicTLS disables the static TLS surplus glibc would otherwise hand a
// module as small as the fixture library, keeping a dlopen'd module's TLS
// dynamic.
var dynamicTLS = []string{"GLIBC_TUNABLES=glibc.rtld.optional_static_tls=0"}

func TestLocateInProcess(t *testing.T) {
	tests := map[string]struct {
		exe string
		// lib is the library the dlopen drivers load, empty otherwise.
		lib string
		env []string
		// wantDynamic requires resolution through the DTV, which is what keeps
		// each case on the access path it was built for.
		wantDynamic bool
	}{
		// local-exec: no relocation, the offset comes from PT_TLS.
		"exe_glibc": {exe: "tlsvar_exe_glibc"},
		"exe_musl":  {exe: "tlsvar_exe_musl"},

		// Libraries linked at startup, so their TLS is part of the initial
		// (static) set even when reached through the dynamic access models.
		"lib_glibc_desc": {exe: "tlsvar_lib_glibc_desc"},
		"lib_musl_desc":  {exe: "tlsvar_lib_musl_desc"},
		"lib_glibc_ie":   {exe: "tlsvar_lib_glibc_ie"},
		"lib_musl_ie":    {exe: "tlsvar_lib_musl_ie"},
		// Initial-exec on hidden symbols: the relocations carrying the
		// runtime-resolved TP offsets become symbol-less.
		"lib_glibc_ie_hidden": {exe: "tlsvar_lib_glibc_ie_hidden"},
		"lib_musl_ie_hidden":  {exe: "tlsvar_lib_musl_ie_hidden"},
		// The GNU dialect resolves through the DTV whichever block the
		// module lands in.
		"lib_glibc_gnu": {exe: "tlsvar_lib_glibc_gnu", wantDynamic: true},
		"lib_musl_gnu":  {exe: "tlsvar_lib_musl_gnu", wantDynamic: true},
		"lib_glibc_ld":  {exe: "tlsvar_lib_glibc_ld", wantDynamic: true},
		"lib_musl_ld":   {exe: "tlsvar_lib_musl_ld", wantDynamic: true},
		// The desc dialect resolves a startup module's descriptor to a TP
		// offset, so these stay static.
		"lib_glibc_ld_desc": {exe: "tlsvar_lib_glibc_ld_desc"},
		"lib_musl_ld_desc":  {exe: "tlsvar_lib_musl_ld_desc"},
		// Static too, but with the offset above the bound below which an
		// argument is an offset on sight, so resolving these takes recognizing
		// the resolver itself. aarch64 only: x86-64 settles it by sign.
		"lib_glibc_desc_big": {exe: "tlsvar_lib_glibc_desc_big"},
		"lib_musl_desc_big":  {exe: "tlsvar_lib_musl_desc_big"},

		// dlopen: the module is loaded after startup, which is what makes its
		// TLS dynamic.
		"dlopen_glibc_desc": {exe: "tlsvar_dlopen_glibc", lib: "libtlsvar_glibc_desc.so",
			env: dynamicTLS, wantDynamic: true},
		"dlopen_glibc_gnu": {exe: "tlsvar_dlopen_glibc", lib: "libtlsvar_glibc_gnu.so",
			env: dynamicTLS, wantDynamic: true},
		"dlopen_musl_desc": {exe: "tlsvar_dlopen_musl", lib: "libtlsvar_musl_desc.so",
			wantDynamic: true},
		"dlopen_musl_gnu": {exe: "tlsvar_dlopen_musl", lib: "libtlsvar_musl_gnu.so",
			wantDynamic: true},
		// Hidden thread-locals in a dlopen'd module: the descriptor's addend
		// reaches Locate through the tls_index offset rather than a TP offset.
		"dlopen_glibc_ld_desc": {exe: "tlsvar_dlopen_glibc", lib: "libtlsvar_glibc_ld_desc.so",
			env: dynamicTLS, wantDynamic: true},
		"dlopen_musl_ld_desc": {exe: "tlsvar_dlopen_musl", lib: "libtlsvar_musl_ld_desc.so",
			wantDynamic: true},
		// Non-PIE: the tls_index the descriptor points at is allocated on a brk
		// heap below 4 GiB, where it is indistinguishable by magnitude from a
		// static TP-relative offset.
		"dlopen_glibc_nopie_desc": {exe: "tlsvar_dlopen_glibc_nopie",
			lib: "libtlsvar_glibc_desc.so", env: dynamicTLS, wantDynamic: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pid, reports := startFixture(t, tc.exe, tc.lib, tc.env)

			pr := process.New(pid, pid)
			t.Cleanup(func() { _ = pr.Close() })
			rm := pr.GetRemoteMemory()

			// Both fixture variables live in the same module.
			mod, bias := findTLSModule(t, pr, "tls_var")
			defer mod.Close()
			dtv := libcDTVInfo(t, pr)

			for varName, rep := range reports {
				sym := tlsSymbol(t, mod, varName)
				v, err := Resolve(mod, sym)
				require.NoError(t, err)
				t.Logf("%s: %v", varName, v)

				info, err := v.Locate(rm, bias)
				require.NoError(t, err)

				dynamic := info.ModuleID() != 0
				require.Equal(t, tc.wantDynamic, dynamic,
					"%s resolved to the wrong kind of TLS", varName)
				if dynamic {
					require.NotZero(t, dtv.Multiplier, "no DTV layout extracted from libc")
					require.NoError(t, info.SetDTVInfo(dtv))
				}

				addr, err := varAddress(rm, info, dtv, rep.tpBase)
				require.NoError(t, err)
				assert.Equal(t, libpf.Address(rep.addr), addr,
					"%s located at the wrong address", varName)
			}
		})
	}
}

// report is one line of fixture output: where the process itself found one of
// its thread-locals, and the thread pointer that address is relative to.
type report struct {
	tpBase uint64
	addr   uint64
}

// startFixture runs one fixture and returns its PID and reports, keyed by
// variable name. The fixture stays blocked, holding the TLS state its loader
// resolved, until the test ends.
func startFixture(t *testing.T, exe, lib string, env []string) (libpf.PID, map[string]report) {
	t.Helper()

	dir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	path := filepath.Join(dir, exe)
	requireFixture(t, path)

	var args []string
	if lib != "" {
		args = append(args, filepath.Join(dir, lib))
	}

	// The fixture never exits on its own, so the timeout is what unblocks a
	// test whose fixture stops short of reporting.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stderr = os.Stderr
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	return libpf.PID(cmd.Process.Pid), readReports(t, stdout)
}

// readReports collects the fixture's variable lines, up to its ready marker.
func readReports(t *testing.T, r io.Reader) map[string]report {
	t.Helper()

	reports := map[string]report{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if sc.Text() == "ready" {
			require.NotEmpty(t, reports)
			return reports
		}
		var name string
		var rep report
		_, err := fmt.Sscanf(sc.Text(), "%s %x %x", &name, &rep.tpBase, &rep.addr)
		require.NoError(t, err, "unexpected fixture output %q", sc.Text())
		require.NotZero(t, rep.tpBase, "fixture failed to read the thread pointer")
		reports[name] = rep
	}
	require.NoError(t, sc.Err())
	t.Fatal("fixture exited without reporting")
	return nil
}

// varAddress follows the descriptor the way dtv_read() in support/ebpf/tsd.h
// does at unwind time. Comparing where that lands against the address the
// fixture reported is what makes the descriptor's correctness observable.
func varAddress(rm remotememory.RemoteMemory, v VarInfo, dtv support.DTVInfo,
	tpBase uint64) (libpf.Address, error) {
	// Signed: variant II puts the static TLS block below the thread pointer.
	offset := libpf.Address(int64(v.TLSOffset()))
	if v.ModuleID() == 0 {
		return libpf.Address(tpBase) + offset, nil
	}

	dtvPtr, err := rm.ReadPtr(libpf.Address(tpBase + uint64(int64(dtv.Offset))))
	if err != nil {
		return 0, err
	}
	block, err := rm.ReadPtr(dtvPtr + libpf.Address(uint64(v.ModuleID())*uint64(dtv.Multiplier)))
	if err != nil {
		return 0, err
	}
	return block + offset, nil
}

// findTLSModule returns the mapped ELF defining name as a thread-local, with
// its load bias, the way the interpreter loader picks a file up per mapping.
func findTLSModule(t *testing.T, pr process.Process, name string) (*pfelf.File, libpf.Address) {
	t.Helper()

	var found *pfelf.File
	var bias libpf.Address
	_, err := pr.IterateMappings(func(m process.RawMapping) bool {
		if !m.IsExecutable() || !m.IsFileBacked() {
			return true
		}
		ef, err := openMappedELF(m)
		if err != nil {
			return true
		}
		if findTLSSymbol(ef, name) == nil {
			_ = ef.Close()
			return true
		}
		mapper := ef.GetAddressMapper()
		elfVaddr, ok := mapper.FileOffsetToVirtualAddress(m.FileOffset)
		require.True(t, ok, "no virtual address for offset %#x of %s", m.FileOffset, m.Path)
		found, bias = ef, libpf.Address(m.Vaddr-elfVaddr)
		return false
	})
	if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
		require.NoError(t, err)
	}
	require.NotNil(t, found, "no mapped ELF defines the thread-local %s", name)
	return found, bias
}

// openMappedELF opens a mapping's backing file from disk, not through
// /proc/<pid>/map_files the way the profiler does: these are the test's own
// files, and map_files needs privileges this test does without.
func openMappedELF(m process.RawMapping) (*pfelf.File, error) {
	return pfelf.Open(m.Path)
}

func tlsSymbol(t *testing.T, ef *pfelf.File, name string) *libpf.Symbol {
	t.Helper()
	sym := findTLSSymbol(ef, name)
	require.NotNil(t, sym, "no thread-local %s", name)
	return sym
}

// findTLSSymbol returns nil unless ef defines name as a thread-local. The
// hidden fixture variables are local symbols, absent from .dynsym, so the
// .symtab walk is not just a fallback here.
func findTLSSymbol(ef *pfelf.File, name string) *libpf.Symbol {
	if ef.ProgByType(elf.PT_TLS) == nil {
		return nil
	}
	var found *libpf.Symbol
	if err := ef.VisitSymbols(func(s libpf.Symbol) bool {
		// Size 0 at address 0 is an undefined entry: a reference to a
		// thread-local another module defines.
		if s.Name != libpf.SymbolName(name) || (s.Size == 0 && s.Address == 0) {
			return true
		}
		found = &s
		return false
	}); err != nil {
		return nil
	}
	return found
}

// libcDTVInfo returns the DTV layout of the process's libc, empty when the
// process has none mapped (a statically linked fixture).
func libcDTVInfo(t *testing.T, pr process.Process) support.DTVInfo {
	t.Helper()

	var dtv support.DTVInfo
	_, err := pr.IterateMappings(func(m process.RawMapping) bool {
		if !m.IsExecutable() || !libc.IsPotentialLibcDSO(m.Path) {
			return true
		}
		ef, err := openMappedELF(m)
		if err != nil {
			return true
		}
		defer ef.Close()
		info, err := libc.ExtractLibcInfo(ef)
		if err != nil || !info.HasDTVInfo() {
			return true
		}
		dtv = info.DTVInfo
		return false
	})
	if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
		require.NoError(t, err)
	}
	return dtv
}
