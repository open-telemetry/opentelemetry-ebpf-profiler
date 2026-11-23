// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestRegisterPTRegsOffset(t *testing.T) {
	tests := []struct {
		name     string
		machine  elf.Machine
		register Register
		want     uint16
	}{
		{name: "amd64 rax", machine: elf.EM_X86_64, register: RegisterRAX,
			want: support.USDTAMD64PtRegsRAXOffset},
		{name: "amd64 rbx", machine: elf.EM_X86_64, register: RegisterRBX,
			want: support.USDTAMD64PtRegsRBXOffset},
		{name: "amd64 rcx", machine: elf.EM_X86_64, register: RegisterRCX,
			want: support.USDTAMD64PtRegsRCXOffset},
		{name: "amd64 rdx", machine: elf.EM_X86_64, register: RegisterRDX,
			want: support.USDTAMD64PtRegsRDXOffset},
		{name: "amd64 rsi", machine: elf.EM_X86_64, register: RegisterRSI,
			want: support.USDTAMD64PtRegsRSIOffset},
		{name: "amd64 rdi", machine: elf.EM_X86_64, register: RegisterRDI,
			want: support.USDTAMD64PtRegsRDIOffset},
		{name: "amd64 rbp", machine: elf.EM_X86_64, register: RegisterRBP,
			want: support.USDTAMD64PtRegsRBPOffset},
		{name: "amd64 rsp", machine: elf.EM_X86_64, register: RegisterRSP,
			want: support.USDTAMD64PtRegsRSPOffset},
		{name: "amd64 r8", machine: elf.EM_X86_64, register: RegisterR8,
			want: support.USDTAMD64PtRegsR8Offset},
		{name: "amd64 r9", machine: elf.EM_X86_64, register: RegisterR9,
			want: support.USDTAMD64PtRegsR9Offset},
		{name: "amd64 r10", machine: elf.EM_X86_64, register: RegisterR10,
			want: support.USDTAMD64PtRegsR10Offset},
		{name: "amd64 r11", machine: elf.EM_X86_64, register: RegisterR11,
			want: support.USDTAMD64PtRegsR11Offset},
		{name: "amd64 r12", machine: elf.EM_X86_64, register: RegisterR12,
			want: support.USDTAMD64PtRegsR12Offset},
		{name: "amd64 r13", machine: elf.EM_X86_64, register: RegisterR13,
			want: support.USDTAMD64PtRegsR13Offset},
		{name: "amd64 r14", machine: elf.EM_X86_64, register: RegisterR14,
			want: support.USDTAMD64PtRegsR14Offset},
		{name: "amd64 r15 at zero", machine: elf.EM_X86_64, register: RegisterR15,
			want: support.USDTAMD64PtRegsR15Offset},
		{name: "amd64 rip", machine: elf.EM_X86_64, register: RegisterRIP,
			want: support.USDTAMD64PtRegsRIPOffset},
		{name: "arm64 x0", machine: elf.EM_AARCH64, register: RegisterX0,
			want: support.USDTARM64PtRegsX0Offset},
		{name: "arm64 x24", machine: elf.EM_AARCH64, register: RegisterX0 + 24,
			want: support.USDTARM64PtRegsX0Offset + 24*support.USDTARM64PtRegsRegisterSize},
		{name: "arm64 x30", machine: elf.EM_AARCH64, register: RegisterX30,
			want: support.USDTARM64PtRegsX0Offset + 30*support.USDTARM64PtRegsRegisterSize},
		{name: "arm64 sp", machine: elf.EM_AARCH64, register: RegisterSP,
			want: support.USDTARM64PtRegsSPOffset},
		{name: "arm64 pc", machine: elf.EM_AARCH64, register: RegisterPC,
			want: support.USDTARM64PtRegsPCOffset},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.register.PTRegsOffset(tc.machine)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRegisterPTRegsOffsetRejectsInvalid(t *testing.T) {
	tests := []struct {
		name     string
		machine  elf.Machine
		register Register
	}{
		{name: "no register on amd64", machine: elf.EM_X86_64, register: RegisterNone},
		{name: "no register on arm64", machine: elf.EM_AARCH64, register: RegisterNone},
		{name: "arm64 register on amd64", machine: elf.EM_X86_64, register: RegisterX0},
		{name: "amd64 register on arm64", machine: elf.EM_AARCH64, register: RegisterRAX},
		{name: "unknown machine", machine: elf.EM_NONE, register: RegisterRAX},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.register.PTRegsOffset(tc.machine)
			assert.Error(t, err)
		})
	}
}
