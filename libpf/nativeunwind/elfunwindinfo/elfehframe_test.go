/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package elfunwindinfo

import (
	"errors"
	"testing"

	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/google/go-cmp/cmp"
)

type ehtester struct {
	t     *testing.T
	res   map[uintptr]sdtypes.UnwindInfo
	found int
}

func (e *ehtester) fdeHook(cie *cieInfo, fde *fdeInfo) bool {
	e.t.Logf("FDE len %d, ciePos %x, ip %x...%x, ipLen %d (enc %x, cf %d, df %d, ra %d)",
		fde.len, fde.ciePos, fde.ipStart, fde.ipStart+fde.ipLen, fde.ipLen,
		cie.enc, cie.codeAlign, cie.dataAlign, cie.regRA)
	e.t.Logf("   LOC           CFA          rbp   ra")
	return true
}

func (e *ehtester) deltaHook(ip uintptr, regs *vmRegs, delta sdtypes.StackDelta) {
	e.t.Logf("%016x %-12s %-5s %s",
		ip,
		regs.cfa.String(),
		regs.fp.String(),
		regs.ra.String())
	if expected, ok := e.res[ip]; ok {
		if diff := cmp.Diff(delta.Info, expected); diff != "" {
			e.t.Fatalf("expected stack delta @%x %s",
				ip, diff)
		}
		e.found++
	}
}

func genDelta(opcode uint8, cfa, rbp int32) sdtypes.UnwindInfo {
	res := sdtypes.UnwindInfo{
		Opcode: opcode,
		Param:  cfa,
	}
	if rbp != 0 {
		res.FPOpcode = sdtypes.UnwindOpcodeBaseCFA
		res.FPParam = -rbp
	}
	return res
}

func deltaRSP(cfa, rbp int32) sdtypes.UnwindInfo {
	return genDelta(sdtypes.UnwindOpcodeBaseSP, cfa, rbp)
}

func deltaRBP(cfa, rbp int32) sdtypes.UnwindInfo {
	return genDelta(sdtypes.UnwindOpcodeBaseFP, cfa, rbp)
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
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			ef, err := pfelf.Open(test.elfFile)
			if err != nil {
				t.Fatalf("Failed to open ELF: %v", err)
			}
			defer ef.Close()

			tester := ehtester{t, test.res, 0}
			deltas := sdtypes.StackDeltaArray{}
			err = parseEHFrame(ef, &deltas, &tester)
			if err != nil {
				t.Fatalf("Failed to parse ELF deltas: %v", err)
			}
			if tester.found != len(test.res) {
				t.Fatalf("Expected %v deltas, got %v", len(test.res), tester.found)
			}
		})
	}
}

// cmpCie is a helper function to compare two cieInfo structs.
func cmpCie(t *testing.T, a, b *cieInfo) bool {
	t.Helper()

	if a.codeAlign != b.codeAlign ||
		a.dataAlign != b.dataAlign ||
		a.regRA != b.regRA ||
		a.enc != b.enc ||
		a.ldsaEnc != b.ldsaEnc ||
		a.hasAugmentation != b.hasAugmentation ||
		a.isSignalHandler != b.isSignalHandler ||
		a.initialState.cfa != b.initialState.cfa ||
		a.initialState.fp != b.initialState.fp ||
		a.initialState.ra != b.initialState.ra {
		return false
	}
	return true
}

func TestParseCIE(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		expected   *cieInfo
		debugFrame bool
		err        error
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
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			fakeReader := &reader{
				debugFrame: tc.debugFrame,
				data:       tc.data,
				end:        uintptr(len(tc.data)),
			}
			extracted := &cieInfo{}
			err := fakeReader.parseCIE(extracted)
			if !errors.Is(err, tc.err) {
				t.Fatal(err)
			}

			if !cmpCie(t, tc.expected, extracted) {
				t.Fatalf("Expected %#v but got %#v", tc.expected, extracted)
			}
		})
	}
}
