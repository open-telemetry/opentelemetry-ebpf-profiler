// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRubyDiscoveryCorpus(t *testing.T) {
	// Captured distro accessors, including their original PCs and provenance.
	// These tests require neither the complete binaries nor network access.
	data, err := os.ReadFile("testdata/discovery.json")
	require.NoError(t, err)
	var cases []struct {
		Name          string
		Kind          string
		Address       uint64
		Code          string
		Slot          uint64
		Resolver      uint64
		Indirect      bool
		SymbolAddress uint64 `json:"symbol_address"`
	}
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			fn := rubyCode(t, tc.Address, tc.Code)
			switch tc.Kind {
			case "amd64-tls":
				access, err := rubyAMDTLSAccess(fn)
				require.NoError(t, err)
				require.Equal(t, rubyTLSAccess{slot: tc.Slot, resolverCall: tc.Resolver, resolverIndirect: tc.Indirect}, access)
			case "arm64-helper", "arm64-inline":
				slot, err := rubyARMECSlot(fn, tc.Kind == "arm64-helper")
				require.NoError(t, err)
				require.Equal(t, tc.Slot, slot)
			case "arm64-symbols":
				address, err := rubySymbolTable(elf.EM_AARCH64, fn)
				require.NoError(t, err)
				require.Equal(t, tc.SymbolAddress, address)
			default:
				t.Fatalf("unknown corpus case %s", tc.Kind)
			}
		})
	}
}

// Ruby 4.0.6 GCC accessor: TPIDR_EL0 + TLSDESC resolver result.
const (
	armPrefix = "3f2303d541d03bd5fd7bbfa9fd030091c025009002f441f900a00f9140003fd6"
	armLoad   = "206860f8"
	armReturn = "fd7bc1a8bf2303d5c0035fd6"
)

func TestRubyDiscoveryClobbers(t *testing.T) {
	for name, code := range map[string]string{
		"unknown-operation":  armPrefix + "000000ca" + armLoad + armReturn, // EOR X0, X0, X0
		"resolver-result":    armPrefix + "e00303aa" + armLoad + armReturn, // MOV X0, X3
		"thread-pointer":     armPrefix + "010080d2" + armLoad + armReturn, // MOV X1, #0
		"stack-restore":      armPrefix + "e007c1a8" + armLoad + armReturn, // LDP X0, X1, [SP], #16
		"return-value":       armPrefix + armLoad + "e00301aa" + armReturn,
		"branch-before-load": armPrefix + "02000014" + armLoad + armReturn,
		"second-resolver": armPrefix + armLoad +
			"c025009002f441f900a00f9140003fd6" + armLoad + armReturn,
	} {
		t.Run("arm64/"+name, func(t *testing.T) {
			_, err := rubyARMECSlot(rubyCode(t, 0x2cbc80, code), true)
			require.Error(t, err)
		})
	}
	for name, between := range map[string]string{
		"pop-result": "58", "overwrite-result": "4889f8", "unknown-operation": "4831c0",
		"branch-before-load": "eb00", "two-pops": "5d5d",
	} {
		t.Run("amd64/"+name, func(t *testing.T) {
			_, err := rubyAMDTLSAccess(rubyCode(t, 0x1000, "488d3de7ffffffe8f4000000"+between+"488b4018c3"))
			require.Error(t, err)
		})
	}
	for name, between := range map[string]string{
		"overwrite-result": "e003012a", "restore-result": "e007c1a8", "unknown-operation": "0000004a",
	} {
		t.Run("symbols/"+name, func(t *testing.T) {
			_, err := rubySymbolTable(elf.EM_AARCH64, rubyCode(t, 0x1000, "000000b0004841b9"+between+"c0035fd6"))
			require.Error(t, err)
		})
	}
}

func rubyCode(t *testing.T, address uint64, code string) rubyFunction {
	t.Helper()
	data, err := hex.DecodeString(code)
	require.NoError(t, err)
	return rubyFunction{address, data}
}

func TestRubyARMECSlot(t *testing.T) {
	fn := rubyCode(t, 0x2cbc80, armPrefix+armLoad+armReturn)
	slot, err := rubyARMECSlot(fn, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0x7833e8), slot)

	for _, off := range []int{4, 20, 24, 28, 32, 44} {
		t.Run(strconv.Itoa(off), func(t *testing.T) {
			bad := rubyFunction{fn.address, append([]byte(nil), fn.code...)}
			bad.code[off] ^= 1 // Wrong TP register, descriptor, call, load or return.
			_, err := rubyARMECSlot(bad, true)
			require.Error(t, err)
		})
	}
	_, err = rubyARMECSlot(rubyFunction{fn.address, fn.code[:47]}, true)
	require.Error(t, err)
}

func TestRubyAMDTLSAccess(t *testing.T) {
	// Ruby 4.0.6 rb_thread_current, including GNU TLS prefixes and volatile EC spill.
	fn := rubyCode(t, 0x265240, "f30f1efa4883ec1866488d3db0382600"+
		"666648e818a2ddff488b004889442408488b442408488b4030488b40104883c418c3")
	access, err := rubyAMDTLSAccess(fn)
	require.NoError(t, err)
	require.Equal(t, rubyTLSAccess{slot: 0x4c8b00, resolverCall: 0x3f470}, access)

	bad := rubyFunction{fn.address, append([]byte(nil), fn.code...)}
	bad.code[26] = 1 // Load from RCX instead of the resolver result in RAX.
	_, err = rubyAMDTLSAccess(bad)
	require.Error(t, err)
	_, err = rubyAMDTLSAccess(rubyFunction{fn.address, append(fn.code, fn.code...)})
	require.Error(t, err, "multiple TLS accesses must not select the first")

	for _, load := range []string{
		"67488b00", // MOV RAX, [EAX] truncates the resolver result to 32 bits.
		"8b00",     // MOV EAX, [RAX] reads only half the EC pointer.
		"65488b00", // MOV RAX, GS:[RAX] is not a dereference of the result.
	} {
		_, err = rubyAMDTLSAccess(rubyCode(t, 0x1000, "488d3de7ffffffe8f4000000"+load+"c3"))
		require.Error(t, err)
	}

	// Local-dynamic code can use a module-base tls_index and a displaced load.
	// The tls_index precedes the code, so the displacement is negative.
	fn = rubyCode(t, 0x1000, "488d3de7ffffffe8f4000000488b4018c3")
	access, err = rubyAMDTLSAccess(fn)
	require.NoError(t, err)
	require.Equal(t, rubyTLSAccess{slot: 0xfee, loadOffset: 24, resolverCall: 0x1100}, access)
}

func TestRubySymbolTable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		machine elf.Machine
		address uint64
		code    string
		want    uint64
	}{
		{"arm64-ruby4", elf.EM_AARCH64, 0x286460, "e02700b00060179100fcdf8800040051c0035fd6", 0x7835d8},
		{"arm64-ruby3", elf.EM_AARCH64, 0x1000, "000000b0004841b9c0035fd6", 0x2148},
		{"amd64-ruby4", elf.EM_X86_64, 0x259970, "f30f1efa8b051624270083e801c3", 0x4cbd90},
		{"amd64-ruby3", elf.EM_X86_64, 0x1000, "8b05fa0f0000c3", 0x2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := rubyCode(t, tc.address, tc.code)
			address, err := rubySymbolTable(tc.machine, fn)
			require.NoError(t, err)
			require.Equal(t, tc.want, address)
			fn.code[len(fn.code)-1] = 0 // Require the complete accessor, including RET.
			_, err = rubySymbolTable(tc.machine, fn)
			require.Error(t, err)
		})
	}
	// The call could clobber X2: without a verified TLSDESC relocation it is not a resolver.
	_, err := rubySymbolTable(elf.EM_AARCH64, rubyCode(t, 0x1000,
		"020000b0000000b0010840f90040009120003fd6404841b9c0035fd6"))
	require.Error(t, err)
}

func TestRubyBranchTargets(t *testing.T) {
	// Ignore an internal loop and a call when looking for a VM tail call.
	fn := rubyCode(t, 0x1000, "ebfee8f9000000e9f40f0000")
	targets, err := rubyBranchTargets(elf.EM_X86_64, fn, false)
	require.NoError(t, err)
	require.Equal(t, map[uint64]bool{0x2000: true}, targets)
	targets, err = rubyBranchTargets(elf.EM_X86_64, fn, true)
	require.NoError(t, err)
	require.Equal(t, map[uint64]bool{0x1100: true}, targets)

	fn = rubyCode(t, 0x1000, "00000014ff030014fe070094")
	targets, err = rubyBranchTargets(elf.EM_AARCH64, fn, false)
	require.NoError(t, err)
	require.Equal(t, map[uint64]bool{0x2000: true}, targets)
	targets, err = rubyBranchTargets(elf.EM_AARCH64, fn, true)
	require.NoError(t, err)
	require.Equal(t, map[uint64]bool{0x3000: true}, targets)
}
