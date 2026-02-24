// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestGetUnwindInfoX86_RegisterRA(t *testing.T) {
	tests := []struct {
		name     string
		regs     vmRegs
		expected sdtypes.UnwindInfo
	}{
		{
			name: "Standard RA=CFA-8",
			regs: vmRegs{
				cfa: vmReg{reg: x86RegRSP, off: 16}, // rsp+16
				ra:  vmReg{reg: regCFA, off: -8},
				fp:  vmReg{reg: regCFA, off: -16},
			},
			expected: sdtypes.UnwindInfo{
				Flags:      0,
				BaseReg:    support.UnwindRegSp,
				Param:      16,
				AuxBaseReg: support.UnwindRegCfa,
				AuxParam:   -16,
			},
		},
		{
			name: "Register-based RA (RDI)",
			regs: vmRegs{
				cfa: vmReg{reg: x86RegRSP, off: 8}, // rsp+8
				ra:  vmReg{reg: x86RegRDI, off: 0},
				fp:  vmReg{reg: regCFA, off: 0},
			},
			expected: sdtypes.UnwindInfo{
				Flags:   support.UnwindFlagRegisterRA,
				BaseReg: support.UnwindRegSp,
				Param:   8,
				RaReg:   support.UnwindRegX86RDI,
			},
		},
		{
			name: "Invalid RA",
			regs: vmRegs{
				cfa: vmReg{reg: x86RegRSP, off: 20},
				ra:  vmReg{reg: regCFA, off: -16}, // Not -8
				fp:  vmReg{reg: regCFA, off: 0},
			},
			expected: sdtypes.UnwindInfoInvalid,
		},
		{
			name: "Exact __vfork FDE: CFA=RSP+0 with RA=RDI",
			regs: vmRegs{
				cfa: vmReg{reg: x86RegRSP, off: 0}, // DW_CFA_def_cfa_offset: 0
				ra:  vmReg{reg: x86RegRDI, off: 0}, // DW_CFA_register: r16 in r5
				fp:  vmReg{reg: regUndefined},      // FP not specified
			},
			expected: sdtypes.UnwindInfo{
				Flags:   support.UnwindFlagRegisterRA,
				BaseReg: support.UnwindRegSp,
				Param:   0,
				RaReg:   support.UnwindRegX86RDI,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.regs.getUnwindInfoX86()
			assert.Equal(t, tt.expected, actual)
		})
	}
}
