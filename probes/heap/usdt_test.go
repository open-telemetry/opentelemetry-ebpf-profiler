// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

func TestParseAllocSpec(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		machine   elf.Machine
	}{
		{name: "amd64 registers", arguments: "8@%r12 8@%r13 8@%r14", machine: elf.EM_X86_64},
		{name: "arm64 registers", arguments: "8@x24 8@x25 8@x28", machine: elf.EM_AARCH64},
		{name: "arm64 stack", arguments: "8@[sp, 40] 8@[sp, 32] 8@[sp, 24]", machine: elf.EM_AARCH64},
		{name: "constant weight", arguments: "8@%rdi 8@%rsi 8@$1", machine: elf.EM_X86_64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parseAllocSpec(usdt.AttachmentPoint{
				Arguments: tc.arguments,
				Machine:   tc.machine,
			})
			require.NoError(t, err)
			assert.Equal(t, uint8(3), spec.Count)
		})
	}
}

func TestParseAllocSpecConvertsToBPF(t *testing.T) {
	spec, err := parseAllocSpec(usdt.AttachmentPoint{
		Arguments: "8@%r12 8@-16(%rbp) 8@$1",
		Machine:   elf.EM_X86_64,
	})
	require.NoError(t, err)
	assert.Equal(t, [3]support.USDTArgumentSpec{
		{Register_offset: support.USDTAMD64PtRegsR12Offset,
			Kind: uint8(usdt.ArgumentRegister)},
		{Value_offset: ^uint64(15), Register_offset: support.USDTAMD64PtRegsRBPOffset,
			Kind: uint8(usdt.ArgumentRegisterDereference)},
		{Value_offset: 1, Kind: uint8(usdt.ArgumentConstant)},
	}, [3]support.USDTArgumentSpec(spec.Arguments[:3]))
}

func TestParseAllocSpecRejectsWrongContract(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
	}{
		{name: "too few", arguments: "8@%rdi 8@%rsi"},
		{name: "signed", arguments: "-8@%rdi 8@%rsi 8@%rdx"},
		{name: "narrow", arguments: "4@%edi 8@%rsi 8@%rdx"},
		{name: "float", arguments: "8f@%rdi 8@%rsi 8@%rdx"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAllocSpec(usdt.AttachmentPoint{
				Arguments: tc.arguments,
				Machine:   elf.EM_X86_64,
			})
			assert.Error(t, err)
		})
	}
}
