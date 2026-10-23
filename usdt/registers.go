// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"debug/elf"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/support"
)

// PTRegsOffset returns the byte offset of r within the Linux pt_regs layout
// for machine. It converts the architecture-independent register identifier
// used by parsed SDT arguments into the representation consumed by eBPF.
func (r Register) PTRegsOffset(machine elf.Machine) (uint16, error) {
	switch machine {
	case elf.EM_X86_64:
		offsets := [...]uint16{
			RegisterRAX: support.USDTAMD64PtRegsRAXOffset,
			RegisterRBX: support.USDTAMD64PtRegsRBXOffset,
			RegisterRCX: support.USDTAMD64PtRegsRCXOffset,
			RegisterRDX: support.USDTAMD64PtRegsRDXOffset,
			RegisterRSI: support.USDTAMD64PtRegsRSIOffset,
			RegisterRDI: support.USDTAMD64PtRegsRDIOffset,
			RegisterRBP: support.USDTAMD64PtRegsRBPOffset,
			RegisterRSP: support.USDTAMD64PtRegsRSPOffset,
			RegisterR8:  support.USDTAMD64PtRegsR8Offset,
			RegisterR9:  support.USDTAMD64PtRegsR9Offset,
			RegisterR10: support.USDTAMD64PtRegsR10Offset,
			RegisterR11: support.USDTAMD64PtRegsR11Offset,
			RegisterR12: support.USDTAMD64PtRegsR12Offset,
			RegisterR13: support.USDTAMD64PtRegsR13Offset,
			RegisterR14: support.USDTAMD64PtRegsR14Offset,
			RegisterR15: support.USDTAMD64PtRegsR15Offset,
			RegisterRIP: support.USDTAMD64PtRegsRIPOffset,
		}
		if r > RegisterNone && int(r) < len(offsets) {
			return offsets[r], nil
		}
	case elf.EM_AARCH64:
		if r >= RegisterX0 && r <= RegisterX30 {
			return support.USDTARM64PtRegsX0Offset +
				uint16(r-RegisterX0)*support.USDTARM64PtRegsRegisterSize, nil
		}
		switch r {
		case RegisterSP:
			return support.USDTARM64PtRegsSPOffset, nil
		case RegisterPC:
			return support.USDTARM64PtRegsPCOffset, nil
		}
	default:
		return 0, fmt.Errorf("unsupported machine %s", machine)
	}
	return 0, fmt.Errorf("register %d is invalid for %s", r, machine)
}
