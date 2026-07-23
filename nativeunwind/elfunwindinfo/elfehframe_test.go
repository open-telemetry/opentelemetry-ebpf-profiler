// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"debug/elf"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ehtester struct {
	t     *testing.T
	res   map[uintptr]sdtypes.UnwindInfo
	found int
}

func (e *ehtester) fdeUnsorted() {
}

func (e *ehtester) fdeHook(cie *cieInfo, fde *fdeInfo, _ *sdtypes.IntervalData) bool {
	e.t.Logf("FDE ciePos %x, ip %x...%x, ipLen %d (enc %x, cf %d, df %d, ra %d)",
		fde.ciePos, fde.ipStart, fde.ipStart+fde.ipLen, fde.ipLen,
		cie.enc, cie.codeAlign, cie.dataAlign, cie.regRA)
	e.t.Logf("   LOC           CFA          rbp   ra")
	return true
}

func (e *ehtester) deltaHook(ip uintptr, regs *vmRegs, info sdtypes.UnwindInfo) {
	e.t.Logf("%016x %-12s %-5s %s",
		ip,
		regs.cfa.String(),
		regs.fp.String(),
		regs.ra.String())
	if expected, ok := e.res[ip]; ok {
		assert.Equal(e.t, expected, info)
		e.found++
	}
}

func (e *ehtester) golangHook(_, _ uintptr) {
}

func genDelta(baseReg uint8, cfa, rbp int32) sdtypes.UnwindInfo {
	res := sdtypes.UnwindInfo{
		BaseReg: baseReg,
		Param:   cfa,
	}
	if rbp != 0 {
		res.AuxBaseReg = support.UnwindRegCfa
		res.AuxParam = -rbp
	}
	return res
}

func deltaRSP(cfa, rbp int32) sdtypes.UnwindInfo {
	return genDelta(support.UnwindRegSp, cfa, rbp)
}

func deltaRBP(cfa, rbp int32) sdtypes.UnwindInfo {
	return genDelta(support.UnwindRegFp, cfa, rbp)
}

func TestEhFrame(t *testing.T) {
	tests := map[string]struct {
		elfFile string
		// Some selected stack delta matches to verify that the ehframe
		// machine is working correctly.
		res map[uintptr]sdtypes.UnwindInfo
	}{
		// test.so is openssl libcrypto.so.1.1's stripped to contain only .eh_frame and
		// .eh_frame_hdr. The current ELF is imported from Alpine Linux
		// openssl-1.1.1g-r0 package's libcrypto.so.1.1:
		//   objcopy -j .eh_frame -j .eh_frame_hdr /lib/libcrypto.so.1.1 test.so
		"libcrypto": {elfFile: "testdata/test.so",
			res: map[uintptr]sdtypes.UnwindInfo{
				0x07631f: deltaRSP(8, 0),
				0x07a0d4: deltaRSP(160, 24),
				0x07b1ec: deltaRSP(8, 0),
				0x088e72: deltaRSP(64, 48),
				0x0a89d9: deltaRBP(16, 16),
				0x0b2ad4: deltaRBP(8, 24),
				0x1c561f: deltaRSP(2160, 48),
			}},
		// schrodinger-libpython3.8.so.1.0 is a stripped version containing only .eh_frame and
		// .eh_frame_hdr from /exports/schrodinger/internal/lib/libpython3.8.so.1.0 - see PF-1538.
		//   objcopy -j .eh_frame -j .eh_frame_hdr /lib/libcrypto.so.1.1 test.so
		"schrodinger-libpython": {elfFile: "testdata/schrodinger-libpython3.8.so.1.0",
			res: map[uintptr]sdtypes.UnwindInfo{
				0x6f805:  deltaRSP(80, 48),
				0x7077c:  deltaRSP(24, 0),
				0x83194:  deltaRSP(64, 16),
				0x954b4:  deltaRSP(48, 48),
				0xc8b9e:  deltaRSP(112, 48),
				0xd2f5e:  deltaRSP(56, 48),
				0xf01cf:  deltaRSP(24, 24),
				0x1a87b2: deltaRSP(40, 40),
				0x23f555: deltaRSP(56, 48),
			}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ef, err := pfelf.Open(test.elfFile)
			require.NoError(t, err)
			defer ef.Close()

			tester := ehtester{t, test.res, 0}
			ee := elfExtractor{
				file:      ef,
				intervals: &sdtypes.IntervalData{},
				hooks:     &tester,
			}
			err = ee.parseEHFrame()
			require.NoError(t, err)
			assert.Equal(t, len(test.res), tester.found)
		})
	}
}

func TestParseCIE(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		expected   *cieInfo
		debugFrame bool
	}{
		// Call frame information example for version 4.
		// http://dwarfstd.org/doc/DWARF5.pdf Table D.5 "Call frame information example"
		"cie 4": {
			debugFrame: true,
			expected: &cieInfo{
				dataAlign: sleb128(-4),
				codeAlign: uleb128(4),
				regRA:     uleb128(8),
			},
			data: []byte{36, 0, 0, 0, // length
				255, 255, 255, 255, // CIE_id
				4,        // version
				0,        // augmentation
				4,        // address size
				0,        // segment size
				4,        // code_alignment_factor
				124,      // data_alignment_factor
				8,        // R8 is the return address
				12, 7, 0, // CFA = [R7]+0
				8, 0, // R0 not modified
				7, 1, // R1 scratch
				7, 2, // R2 scratch
				7, 3, // R3 scratch
				8, 4, // R4 preserve
				8, 5, // R5 preserve
				8, 6, // R6 preserve
				8, 7, // R7 preserve
				9, 8, 1, // R8 is in R1
				0, // DW_CFA_nop
				0, // DW_CFA_nop
				0, // DW_CFA_nop
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeReader := &reader{
				debugFrame: tc.debugFrame,
				data:       tc.data,
				end:        uintptr(len(tc.data)),
			}
			extracted := &cieInfo{}
			err := fakeReader.parseCIE(extracted)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, extracted)
		})
	}
}

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
				Flags:      support.UnwindFlagRegisterRA | support.UnwindFlagLeafOnly,
				BaseReg:    support.UnwindRegSp,
				Param:      8,
				AuxBaseReg: support.UnwindRegX86RDI,
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
				Flags:      support.UnwindFlagRegisterRA | support.UnwindFlagLeafOnly,
				BaseReg:    support.UnwindRegSp,
				Param:      0,
				AuxBaseReg: support.UnwindRegX86RDI,
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

// TestReaderStrUnterminated verifies that reader.str() does not index its
// backing slice out of bounds when the input contains no NUL terminator within
// the reader's bounds (e.g. a CIE augmentation string at the tail of a
// truncated/crafted .eh_frame section). Such input must be reported as an
// overread (isValid() == false) so the caller rejects the record, rather than
// panicking and crashing the profiler. Regression test for the unbounded scan
// in (*reader).str().
func TestReaderStrUnterminated(t *testing.T) {
	t.Run("unterminated does not panic and signals overread", func(t *testing.T) {
		// No 0x00 byte anywhere in the region.
		data := []byte{'z', 'R', 0xff, 0xff}
		r := &reader{data: data, pos: 0, end: uintptr(len(data))}
		require.NotPanics(t, func() { _ = r.str() })
		assert.False(t, r.isValid(),
			"reader must be marked invalid (overread) when no terminator is found")
	})

	t.Run("terminated string still parses normally", func(t *testing.T) {
		data := []byte{'z', 'R', 0x00, 0x42}
		r := &reader{data: data, pos: 0, end: uintptr(len(data))}
		var s []byte
		require.NotPanics(t, func() { s = r.str() })
		assert.Equal(t, []byte("zR"), s)
		assert.True(t, r.isValid())
		assert.Equal(t, uintptr(3), r.pos, "pos must advance past the NUL")
	})

	t.Run("terminator at last byte is in-bounds", func(t *testing.T) {
		data := []byte{'a', 0x00}
		r := &reader{data: data, pos: 0, end: uintptr(len(data))}
		require.NotPanics(t, func() { _ = r.str() })
		assert.True(t, r.isValid())
	})
}

func TestEntryDetection(t *testing.T) {
	testCases := map[string]struct {
		machine elf.Machine
		code    []byte
		len     int
	}{
		"musl 1.2.5 / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				// 1. assembly code from crt_arch.h (no FDE at all):
				// 48 31 ed             xor    %rbp,%rbp
				// 48 89 e7             mov    %rsp,%rdi
				// 48 8d 35 b2 c2 00 00 lea    0xc2b2(%rip),%rsi
				// 48 83 e4 f0          and    $0xfffffffffffffff0,%rsp
				// e8 00 00 00 00       call   0x4587
				// 2. followed with C code from [r]crt1.c (maybe with FDE):
				// 8b 37                mov    (%rdi),%esi
				// 48 8d 57 08          lea    0x8(%rdi),%rdx
				// 4c 8d 05 d0 62 00 00 lea    0x62d0(%rip),%r8
				// 45 31 c9             xor    %r9d,%r9d
				// 48 8d 0d 62 fa ff ff lea    -0x59e(%rip),%rcx
				// 48 8d 3d 8b fa ff ff lea    -0x575(%rip),%rdi
				// e9 76 fa ff ff       jmp    0x4020 <__libc_start_main@plt>
				0x48, 0x31, 0xed, 0x48, 0x89, 0xe7, 0x48, 0x8d,
				0x35, 0xb2, 0xc2, 0x00, 0x00, 0x48, 0x83, 0xe4,
				0xf0, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x37,
				0x48, 0x8d, 0x57, 0x08, 0x4c, 0x8d, 0x05, 0xd0,
				0x62, 0x00, 0x00, 0x45, 0x31, 0xc9, 0x48, 0x8d,
				0x0d, 0x62, 0xfa, 0xff, 0xff, 0x48, 0x8d, 0x3d,
				0x8b, 0xfa, 0xff, 0xff, 0xe9, 0x76, 0xfa, 0xff,
				0xff,
			},
			len: 57,
		},
		"musl 1.2.5 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				// 1. assembly code from crt_arch.h (no FDE):
				// mov	x29, #0x0
				// mov	x30, #0x0
				// mov	x0, sp
				// adrp	x1, 0x1f000
				// add	x1, x1, #0x7d0
				// and	sp, x0, #0xfffffffffffffff0
				// b	0x413c
				// 2. followed with C code from [r]crt1.c (no FDE):
				// mov	x2, x0
				// mov	x5, #0x0
				// adrp	x4, 0x1f000
				// ldr	x4, [x4, #3928]
				// ldr	x1, [x2], #8
				// adrp	x3, 0x1f000
				// ldr	x3, [x3, #4080]
				// adrp	x0, 0x1f000
				// ldr	x0, [x0, #4072]
				// b	0x35a0 <__libc_start_main@plt>
				0x1d, 0x00, 0x80, 0xd2, 0x1e, 0x00, 0x80, 0xd2,
				0xe0, 0x03, 0x00, 0x91, 0xc1, 0x00, 0x00, 0xf0,
				0x21, 0x40, 0x1f, 0x91, 0x1f, 0xec, 0x9c, 0x92,
				0x01, 0x00, 0x00, 0x14, 0xe2, 0x03, 0x00, 0xaa,
				0x05, 0x00, 0x80, 0xd2, 0xc3, 0x00, 0x00, 0xf0,
				0x84, 0xac, 0x47, 0xf9, 0x41, 0x84, 0x40, 0xf8,
				0xc3, 0x00, 0x00, 0xf0, 0x63, 0xf8, 0x47, 0xf9,
				0xc0, 0x00, 0x00, 0xf0, 0x00, 0xf4, 0x47, 0xf9,
				0x10, 0xfd, 0xff, 0x17,
			},
			len: 68,
		},
		"glibc 2.31 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				// mov	x29, #0x0
				// mov	x30, #0x0
				// mov	x5, x0
				// ldr	x1, [sp]
				// add	x2, sp, #0x8
				// mov	x6, sp
				// adrp	x0, 0x11000
				// ldr	x0, [x0, #4064]
				// adrp	x3, 0x11000
				// ldr	x3, [x3, #4056]
				// adrp	x4, 0x11000
				// ldr	x4, [x4, #4008]
				// bl	0xa90 <__libc_start_main@plt>
				// bl	0xae0 <abort@plt>
				0x1d, 0x00, 0x80, 0xd2, 0x1e, 0x00, 0x80, 0xd2,
				0xe5, 0x03, 0x00, 0xaa, 0xe1, 0x03, 0x40, 0xf9,
				0xe2, 0x23, 0x00, 0x91, 0xe6, 0x03, 0x00, 0x91,
				0x80, 0x00, 0x00, 0xb0, 0x00, 0xf0, 0x47, 0xf9,
				0x83, 0x00, 0x00, 0xb0, 0x63, 0xec, 0x47, 0xf9,
				0x84, 0x00, 0x00, 0xb0, 0x84, 0xd4, 0x47, 0xf9,
				0xab, 0xff, 0xff, 0x97, 0xbe, 0xff, 0xff, 0x97,
			},
			len: 56,
		},
		"glibc 2.35 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				// mov	x29, #0x0
				// mov	x30, #0x0
				// mov	x5, x0
				// ldr	x1, [sp]
				// add	x2, sp, #0x8
				// mov	x6, sp
				// movz	x0, #0x0, lsl #48
				// movk	x0, #0x0, lsl #32
				// movk	x0, #0xb9, lsl #16
				// movk	x0, #0x1f90
				// movz	x3, #0x0, lsl #48
				// movk	x3, #0x0, lsl #32
				// movk	x3, #0x236, lsl #16
				// movk	x3, #0x65d0
				// movz	x4, #0x0, lsl #48
				// movk	x4, #0x0, lsl #32
				// movk	x4, #0x236, lsl #16
				// movk	x4, #0x6650
				// bl	0xb614e0 <__libc_start_main@plt>
				// bl	0xb61460 <abort@plt>
				0x1d, 0x00, 0x80, 0xd2, 0x1e, 0x00, 0x80, 0xd2,
				0xe5, 0x03, 0x00, 0xaa, 0xe1, 0x03, 0x40, 0xf9,
				0xe2, 0x23, 0x00, 0x91, 0xe6, 0x03, 0x00, 0x91,
				0x00, 0x00, 0xe0, 0xd2, 0x00, 0x00, 0xc0, 0xf2,
				0x20, 0x17, 0xa0, 0xf2, 0x00, 0xf2, 0x83, 0xf2,
				0x03, 0x00, 0xe0, 0xd2, 0x03, 0x00, 0xc0, 0xf2,
				0xc3, 0x46, 0xa0, 0xf2, 0x03, 0xba, 0x8c, 0xf2,
				0x04, 0x00, 0xe0, 0xd2, 0x04, 0x00, 0xc0, 0xf2,
				0xc4, 0x46, 0xa0, 0xf2, 0x04, 0xca, 0x8c, 0xf2,
				0x7d, 0x1c, 0xff, 0x97, 0x5c, 0x1c, 0xff, 0x97,
			},
			len: 80,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			entryLen := detectEntryCode(test.machine, test.code)
			assert.Equal(t, test.len, entryLen)
		})
	}
}
