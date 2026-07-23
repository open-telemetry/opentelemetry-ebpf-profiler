// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/arch/arm64/arm64asm"
)

type armExtractor struct {
	ef *pfelf.File
}

var _ extractor = &armExtractor{}

// Return true if the code in b calls targetCall.
func (a *armExtractor) callExists(b []byte, baseAddr, targetCall int64) (bool, error) {
	var ip int64
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return false, err
		}
		if i.Op == arm64asm.BL {
			a0, ok := i.Args[0].(arm64asm.PCRel)
			if ok {
				result := baseAddr + ip + int64(a0)
				if result == targetCall {
					return true, nil
				}
			}
		}
		ip += 4
	}
	return false, nil
}

// This function gets the glref offset from the first load and the
// cur_L offset from the last store instruction. It's not resilient
// to arbitrary register movement/spilling but seems to work.
//
// (lldb) dis -n lua_close
// libluajit-5.1.so`lua_close:
// libluajit-5.1.so[0x15c20] <+0>:   stp    x19, x20, [sp, #-0x30]!
// libluajit-5.1.so[0x15c24] <+4>:   ldr    x20, [x0, #0x10] ; 0x10 is glrefOffset
// libluajit-5.1.so[0x15c28] <+8>:   stp    x21, x22, [sp, #0x10]
// libluajit-5.1.so[0x15c2c] <+12>:  adrp   x21, 0
// libluajit-5.1.so[0x15c30] <+16>:  mov    w22, #0xa ; =10
// libluajit-5.1.so[0x15c34] <+20>:  add    x21, x21, #0x7d4
// libluajit-5.1.so[0x15c38] <+24>:  ldr    x19, [x20, #0xc0]
// libluajit-5.1.so[0x15c3c] <+28>:  str    x30, [sp, #0x20]
// libluajit-5.1.so[0x15c40] <+32>:  mov    x0, x19
// libluajit-5.1.so[0x15c44] <+36>:  bl     0x8040         ; symbol stub for: luaJIT_profile_start
// libluajit-5.1.so[0x15c48] <+40>:  ldr    x1, [x19, #0x38]
// libluajit-5.1.so[0x15c4c] <+44>:  str    xzr, [x20, #0x170]  ; 0x170 is curLOffset
func (a *armExtractor) findOffsetsFromLuaClose(b []byte) (glref, curL uint64, err error) {
	greg := -1
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, 0, err
		}
		// ldr    x20, [x0, #0x10] ; 0x10 is glrefOffset
		if i.Op == arm64asm.LDR && greg == -1 {
			a1, ok := i.Args[1].(arm64asm.MemImmediate)
			if imm, ok2 := arm.DecodeImmediate(a1); ok && ok2 {
				if a0, ok3 := arm.Xreg2num(i.Args[0]); ok3 {
					greg = a0
					glref = uint64(imm)
				}
			}
		}
		if i.Op == arm64asm.STR {
			a1, ok := i.Args[1].(arm64asm.MemImmediate)
			if regnum, ok2 := arm.Xreg2num(a1.Base); ok && ok2 && regnum == greg && i.Args[0] == arm64asm.XZR {
				if imm, ok3 := arm.DecodeImmediate(a1); ok3 {
					curL = uint64(imm)
					break
				}
			}
		}
	}
	return glref, curL, nil
}

// libluajit-5.1.so[0x145e4] <+4>:   mov    x19, x0
// ...
// libluajit-5.1.so[0x14660] <+128>: add    x3, x19, #0xf38
func (a *armExtractor) findG2DispatchOffsetFromLjDispatchUpdate(b []byte) (uint64, error) {
	greg := 0 // X0 as returned by Xreg2num
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		// Update greg if it moves
		if i.Op == arm64asm.MOV {
			a0, ok0 := arm.Xreg2num(i.Args[0])
			a1, ok1 := arm.Xreg2num(i.Args[1])
			// a1 == X0
			if ok0 && ok1 && a1 == 0 {
				greg = a0
			}
		}
		if i.Op == arm64asm.ADD {
			if a1, ok := arm.Xreg2num(i.Args[1]); ok && a1 == greg {
				if imm, ok := arm.DecodeImmediate(i.Args[2]); ok {
					return uint64(imm), nil
				}
			}
		}
	}
	return 0, errors.New("g to dispatch offset not found")
}

func (a *armExtractor) findLjDispatchUpdateAddr(b []byte, addr uint64) (uint64, error) {
	var ip int64
	for len(b) > 0 {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.BL {
			a0, ok := i.Args[0].(arm64asm.PCRel)
			if ok {
				offset := int64(a0)
				result := int64(addr) + ip + offset
				return uint64(result), nil
			}
		}
		ip += 4
		b = b[4:]
	}
	return 0, errors.New("no calls in code")
}

// libluajit-5.1.so`lj_cf_jit_util_traceinfo:
// libluajit-5.1.so[0x67a44] <+0>:   stp    x19, x20, [sp, #-0x40]!
// libluajit-5.1.so[0x67a48] <+4>:   mov    w1, #0x1 ; =1
// libluajit-5.1.so[0x67a4c] <+8>:   mov    x19, x0
// libluajit-5.1.so[0x67a50] <+12>:  str    x30, [sp, #0x30]
// libluajit-5.1.so[0x67a54] <+16>:  bl     0x5adf0        ; lj_lib_checkint at lj_lib.c:242:1
// libluajit-5.1.so[0x67a58] <+20>:  cbz    w0, 0x67be8 ; <+420> at lib_jit.c:381:10
// libluajit-5.1.so[0x67a5c] <+24>:  ldr    x2, [x19, #0x10]   ;; This loads global
// libluajit-5.1.so[0x67a60] <+28>:  mov    w1, w0
// libluajit-5.1.so[0x67a64] <+32>:  mov    w0, #0x0 ; =0
// libluajit-5.1.so[0x67a68] <+36>:  add    x2, x2, #0x2e0     ;; This is global to J offset
// libluajit-5.1.so[0x67a6c] <+40>:  ldr    w3, [x2, #0x174]   ;; This is checking J->sztraces != 0
// libluajit-5.1.so[0x67a70] <+44>:  cmp    w1, w3
// libluajit-5.1.so[0x67a74] <+48>:  b.hs   0x67bdc        ; <+408> at lib_jit.c:382:1
// libluajit-5.1.so[0x67a78] <+52>:  ldr    x2, [x2, #0x168]   ;; This is J->trace
// So for this version we want 0x2e0 + 0x168
func (a *armExtractor) findG2TracesOffsetFromChecktrace(b []byte) (uint64, error) {
	var g2JOffset uint64
	reg := -1
	sawSZTraceLoad := false
	for len(b) > 0 {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.LDR {
			a1, ok := i.Args[1].(arm64asm.MemImmediate)
			if ok {
				if imm, immOk := arm.DecodeImmediate(a1); immOk {
					if imm == 0x10 {
						if dst, dstOk := arm.Xreg2num(i.Args[0]); dstOk {
							reg = dst
						}
					} else if base, baseOk := arm.Xreg2num(a1.Base); baseOk && base == reg {
						// Skip over load of sztraces
						if sawSZTraceLoad {
							return g2JOffset + uint64(imm), nil
						}
						sawSZTraceLoad = true
					}
				}
			}
		}
		if i.Op == arm64asm.ADD {
			if a1, ok := arm.Xreg2num(i.Args[1]); ok && a1 == reg {
				if imm, ok := arm.DecodeImmediate(i.Args[2]); ok {
					g2JOffset = uint64(imm)
				}
			}
		}
		b = b[4:]
	}
	return 0, errors.New("offset not found")
}

func (a *armExtractor) find2ndArgTo2ndPushClosureCall(b []byte, baseAddr, targetCall int64) (uint64, error) {
	var ip, x1 int64
	var seenFirst bool
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.BL {
			a0, ok := i.Args[0].(arm64asm.PCRel)
			if ok {
				result := baseAddr + ip + int64(a0)
				if result == targetCall {
					if seenFirst {
						return uint64(x1), nil
					}
					seenFirst = true
				}
			}
		}
		if i.Op == arm64asm.ADRP {
			a1, ok := i.Args[1].(arm64asm.PCRel)
			if ok {
				if a0, ok2 := arm.Xreg2num(i.Args[0]); ok2 && a0 == 1 /* X1 */ {
					// zero lower 12 bits of addr+ip
					x1 = (baseAddr + ip) & ^0xfff
					x1 += int64(a1)
				}
			}
		}
		if i.Op == arm64asm.ADD {
			a0, ok1 := arm.Xreg2num(i.Args[0])
			a1, ok2 := arm.Xreg2num(i.Args[1])
			// a1 == X1 && a0 == a1
			if ok1 && ok2 && a1 == 1 && a0 == a1 {
				if imm, ok := arm.DecodeImmediate(i.Args[2]); ok {
					x1 += imm
				}
			}
		}
		ip += 4
	}
	return 0, errors.New("failed to find 2nd arg to 2nd lua_pushcclosure call")
}

// luaopen_jit looks like this.  ___lldb_unnamed_symbol1372 is lj_lib_prereg, the 2nd call to it
// is for luaopen_jit_util, so we want to get the address that is constructed in the x2 register
// and return it.
//
// Source:
// https://github.com/openresty/luajit2/blob/7952882d9/src/lib_jit.c#L803
//
// libluajit-5.1.so[0x64d88] <+168>: add    x2, x20, #0xd0
// libluajit-5.1.so[0x64d8c] <+172>: add    x3, x21, #0xb8
// libluajit-5.1.so[0x64d90] <+176>: mov    x0, x19
// libluajit-5.1.so[0x64d94] <+180>: adrp   x1, 8
// libluajit-5.1.so[0x64d98] <+184>: add    x1, x1, #0xa28
// libluajit-5.1.so[0x64d9c] <+188>: bl     0x57e50        ; ___lldb_unnamed_symbol1370
// libluajit-5.1.so[0x64da0] <+192>: ldr    x3, [x19, #0x48]
// libluajit-5.1.so[0x64da4] <+196>: mov    x0, x19
// libluajit-5.1.so[0x64da8] <+200>: adrp   x2, -1
// libluajit-5.1.so[0x64dac] <+204>: adrp   x1, 8
// libluajit-5.1.so[0x64db0] <+208>: add    x2, x2, #0x338
// libluajit-5.1.so[0x64db4] <+212>: add    x1, x1, #0xa30
// libluajit-5.1.so[0x64db8] <+216>: bl     0x58320        ; ___lldb_unnamed_symbol1372
// libluajit-5.1.so[0x64dbc] <+220>: ldr    x3, [x19, #0x48]
// libluajit-5.1.so[0x64dc0] <+224>: mov    x0, x19
// libluajit-5.1.so[0x64dc4] <+228>: adrp   x2, -1
// libluajit-5.1.so[0x64dc8] <+232>: adrp   x1, 8
// libluajit-5.1.so[0x64dcc] <+236>: add    x2, x2, #0x310
// libluajit-5.1.so[0x64dd0] <+240>: add    x1, x1, #0xa40
// libluajit-5.1.so[0x64dd4] <+244>: bl     0x58320        ; ___lldb_unnamed_symbol1372
// libluajit-5.1.so[0x64dd8] <+248>: add    x3, x21, #0xf0
// libluajit-5.1.so[0x64ddc] <+252>: add    x2, x20, #0x130
// libluajit-5.1.so[0x64de0] <+256>: mov    x0, x19
// libluajit-5.1.so[0x64de4] <+260>: adrp   x1, 8
// libluajit-5.1.so[0x64de8] <+264>: add    x1, x1, #0xa50
// libluajit-5.1.so[0x64dec] <+268>: bl     0x57e50        ; ___lldb_unnamed_symbol1370
//
// So we track adrp and add instructions touching x2 and return that value when we see
// a repeat BL call. In this case:
// [0x64dc4] <+228>: adrp   x2, -1           --> x2 becomes 0x63000
// [0x64dcc] <+236>: add    x2, x2, #0x310   --> x2 becomes 0x63310
func (a *armExtractor) find3rdArgToLibPreregCall(b []byte, addr int64) (uint64, error) {
	var ip, x2, prevCall int64
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.BL {
			a0, ok := i.Args[0].(arm64asm.PCRel)
			if ok {
				result := addr + ip + int64(a0)
				// There's also two back-to-back calls to lua_copy, ignore those
				// by requiring x2 to have been set.
				if result == prevCall && x2 != 0 {
					return uint64(x2), nil
				}
				prevCall = result
			}
		}
		if i.Op == arm64asm.ADRP {
			a1, ok := i.Args[1].(arm64asm.PCRel)
			if ok {
				if a0, ok2 := arm.Xreg2num(i.Args[0]); ok2 && a0 == 2 { // X2
					// zero lower 12 bits of addr+ip
					x2 = (addr + ip) & ^0xfff
					x2 += int64(a1)
				}
			}
		}
		if i.Op == arm64asm.ADD {
			a0, ok1 := arm.Xreg2num(i.Args[0])
			a1, ok2 := arm.Xreg2num(i.Args[1])
			// a1 == X2 && a0 == a1
			if ok1 && ok2 && a1 == 2 && a0 == a1 {
				if imm, ok := arm.DecodeImmediate(i.Args[2]); ok {
					x2 += imm
				}
			}
		}
		ip += 4
	}
	return 0, errors.New("failed to find 3rd arg to lib prereg call")
}

// The 4th arg to lj_lib_register is lj_lib_cf_jit_util which is a function array.
// Track the adrp/add combo the x3 register to get it.
//
// Source:
// https://github.com/openresty/luajit2/blob/7952882/src/lib_jit.c#L486
//
// libluajit-5.1.so`___lldb_unnamed_symbol1577:
// libluajit-5.1.so[0x63310] <+0>:  str    x30, [sp, #-0x10]!
// libluajit-5.1.so[0x63314] <+4>:  mov    x1, #0x0 ; =0
// libluajit-5.1.so[0x63318] <+8>:  adrp   x3, 43
// libluajit-5.1.so[0x6331c] <+12>: adrp   x2, 9
// libluajit-5.1.so[0x63320] <+16>: add    x3, x3, #0xfc8
// libluajit-5.1.so[0x63324] <+20>: add    x2, x2, #0x740
// libluajit-5.1.so[0x63328] <+24>: bl     0x57e50        ; ___lldb_unnamed_symbol1370
// libluajit-5.1.so[0x6332c] <+28>: mov    w0, #0x1 ; =1
// libluajit-5.1.so[0x63330] <+32>: ldr    x30, [sp], #0x10
// libluajit-5.1.so[0x63334] <+36>: ret
func (a *armExtractor) find4thArgToLibRegCall(b []byte, addr int64) (int64, error) {
	var ip, x3 int64
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.ADRP {
			a1, ok := i.Args[1].(arm64asm.PCRel)
			if ok {
				if a0, ok2 := arm.Xreg2num(i.Args[0]); ok2 && a0 == 3 { // X3
					// zero lower 12 bits of addr+ip
					x3 = (addr + ip) & ^0xfff
					x3 += int64(a1)
				}
			}
		}
		if i.Op == arm64asm.ADD {
			a0, ok1 := arm.Xreg2num(i.Args[0])
			a1, ok2 := arm.Xreg2num(i.Args[1])
			// a1 == X3 && a0 == a1
			if ok1 && ok2 && a1 == 3 && a0 == a1 {
				if imm, ok := arm.DecodeImmediate(i.Args[2]); ok {
					// Note: don't return yet, since sometimes there's actually
					// multiple add instructions affecting the register before we finally get
					// to the `bl`.
					x3 += imm
				}
			}
		}
		if i.Op == arm64asm.BL {
			if x3 != 0 {
				return x3, nil
			}
		}
		ip += 4
	}
	return 0, errors.New("failed to find 4th arg to lj_lib_register call")
}

func (a *armExtractor) findFirstCall(b []byte, addr int64) (uint64, error) {
	var ip int64
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.BL {
			a0, ok := i.Args[0].(arm64asm.PCRel)
			if ok {
				result := addr + ip + int64(a0)
				return uint64(result), nil
			}
		}
		ip += 4
	}
	return 0, errors.New("no calls found")
}
