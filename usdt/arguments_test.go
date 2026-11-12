// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArguments(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		machine elf.Machine
		want    []ArgumentSpec
	}{
		{
			name:    "amd64 registers",
			raw:     "8@%r12 8@%r13 8@%r14",
			machine: elf.EM_X86_64,
			want: []ArgumentSpec{
				{Kind: ArgumentRegister, Register: RegisterR12},
				{Kind: ArgumentRegister, Register: RegisterR13},
				{Kind: ArgumentRegister, Register: RegisterR14},
			},
		},
		{
			name:    "amd64 register dereference and constant",
			raw:     "-4@-24(%rbp) 8@(%rsp) 8@$42",
			machine: elf.EM_X86_64,
			want: []ArgumentSpec{
				{ValueOffset: ^uint64(23), Kind: ArgumentRegisterDereference,
					Register: RegisterRBP, Signed: 1, BitShift: 32},
				{Kind: ArgumentRegisterDereference, Register: RegisterRSP},
				{ValueOffset: 42, Kind: ArgumentConstant},
			},
		},
		{
			name:    "amd64 uppercase register and signed constant",
			raw:     "8@%RDI -4@$-24",
			machine: elf.EM_X86_64,
			want: []ArgumentSpec{
				{Kind: ArgumentRegister, Register: RegisterRDI},
				{ValueOffset: ^uint64(23), Kind: ArgumentConstant, Signed: 1, BitShift: 32},
			},
		},
		{
			name:    "amd64 narrow register aliases and float marker",
			raw:     "1@%al 2f@%ax",
			machine: elf.EM_X86_64,
			want: []ArgumentSpec{
				{Kind: ArgumentRegister, Register: RegisterRAX, BitShift: 56},
				{Kind: ArgumentRegister, Register: RegisterRAX, BitShift: 48, Float: 1},
			},
		},
		{
			name:    "compiler-style unsigned constants",
			raw:     "1@-1 8@-9223372036854775808",
			machine: elf.EM_AARCH64,
			want: []ArgumentSpec{
				{ValueOffset: ^uint64(0), Kind: ArgumentConstant, BitShift: 56},
				{ValueOffset: uint64(1) << 63, Kind: ArgumentConstant},
			},
		},
		{
			name:    "zero arguments",
			raw:     "",
			machine: elf.EM_X86_64,
			want:    []ArgumentSpec{},
		},
		{
			name:    "arm64 registers",
			raw:     "8@x24 8@x25 8@x28",
			machine: elf.EM_AARCH64,
			want: []ArgumentSpec{
				{Kind: ArgumentRegister, Register: RegisterX0 + 24},
				{Kind: ArgumentRegister, Register: RegisterX0 + 25},
				{Kind: ArgumentRegister, Register: RegisterX0 + 28},
			},
		},
		{
			name:    "arm64 32-bit register aliases",
			raw:     "4@w0 4@wsp",
			machine: elf.EM_AARCH64,
			want: []ArgumentSpec{
				{Kind: ArgumentRegister, Register: RegisterX0, BitShift: 32},
				{Kind: ArgumentRegister, Register: RegisterSP, BitShift: 32},
			},
		},
		{
			name:    "arm64 stack dereferences",
			raw:     "8@[sp, 40] 8@[sp, 32] 8@[sp, 24]",
			machine: elf.EM_AARCH64,
			want: []ArgumentSpec{
				{ValueOffset: 40, Kind: ArgumentRegisterDereference, Register: RegisterSP},
				{ValueOffset: 32, Kind: ArgumentRegisterDereference, Register: RegisterSP},
				{ValueOffset: 24, Kind: ArgumentRegisterDereference, Register: RegisterSP},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseArguments(tc.raw, tc.machine)
			require.NoError(t, err)
			require.Equal(t, uint8(len(tc.want)), got.ArgumentCount)
			assert.Equal(t, tc.want, got.Arguments[:len(tc.want)])
		})
	}
}

func TestParseArgumentsRejectsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		machine elf.Machine
	}{
		{name: "unknown architecture", raw: "8@x0", machine: elf.EM_NONE},
		{name: "unknown register", raw: "8@x31", machine: elf.EM_AARCH64},
		{name: "bad width", raw: "3@%rdi", machine: elf.EM_X86_64},
		{name: "unbalanced", raw: "8@[sp, 40", machine: elf.EM_AARCH64},
		{name: "unsupported location", raw: "8@symbol", machine: elf.EM_X86_64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArguments(tc.raw, tc.machine)
			assert.Error(t, err)
		})
	}
}

func FuzzParseArguments(f *testing.F) {
	f.Add("8@%rdi 8@%rsi 8@%rdx", uint16(elf.EM_X86_64))
	f.Add("1@-1 2f@%ax", uint16(elf.EM_X86_64))
	f.Add("8@[sp, 40] 4@w0", uint16(elf.EM_AARCH64))
	f.Fuzz(func(_ *testing.T, raw string, machine uint16) {
		_, _ = ParseArguments(raw, elf.Machine(machine))
	})
}
