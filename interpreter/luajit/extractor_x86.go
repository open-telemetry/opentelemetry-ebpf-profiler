// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"errors"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/arch/x86/x86asm"
)

type x86Extractor struct {
	ef *pfelf.File
}

var _ extractor = &x86Extractor{}

/*
*
Dump of assembler code for function lua_close:

Get the offset global_State pointer in lua_State (glref) and the offset
of the lua_State pointer in global_State (cur_L) from the disassembly of lua_close
which is a dynamic public symbol that should be in all binaries of LuaJIT including stripped.

	0x0000000000016d80 <+0>:     push   %r13
	0x0000000000016d82 <+2>:     push   %r12
	0x0000000000016d84 <+4>:     lea    -0x33b(%rip),%r12        # 0x16a50
	0x0000000000016d8b <+11>:    push   %rbp
	0x0000000000016d8c <+12>:    push   %rbx
	0x0000000000016d8d <+13>:    mov    $0xa,%r13d
	0x0000000000016d93 <+19>:    sub    $0x8,%rsp
	0x0000000000016d97 <+23>:    mov    0x10(%rdi),%rbp  ; 0x10 is the glrefOffset
	0x0000000000016d9b <+27>:    mov    0xc0(%rbp),%rbx
	0x0000000000016da2 <+34>:    mov    %rbx,%rdi
	0x0000000000016da5 <+37>:    call   0x1f6f0 <luaJIT_profile_stop>
	0x0000000000016daa <+42>:    mov    0x38(%rbx),%rsi
	0x0000000000016dae <+46>:    mov    %rbx,%rdi
	0x0000000000016db1 <+49>:    movq   $0x0,0x170(%rbp)  ; 0x170 is curLOffset
*/
//nolint:nonamedreturns
func (x *x86Extractor) findOffsetsFromLuaClose(b []byte) (glref, curL uint64, err error) {
	b, _ = skipEndBranch(b)
	var greg x86asm.Reg
	for len(b) > 0 {
		var i x86asm.Inst
		i, err = x86asm.Decode(b, 64)
		if err != nil {
			return 0, 0, err
		}
		if i.Op == x86asm.MOV {
			if greg == 0 {
				a0, ok1 := i.Args[0].(x86asm.Reg)
				a1, ok2 := i.Args[1].(x86asm.Mem)
				if ok1 && ok2 && a1.Base == x86asm.RDI {
					greg = a0
					glref = uint64(a1.Disp)
				}
			} else {
				a0, ok1 := i.Args[0].(x86asm.Mem)
				a1, ok2 := i.Args[1].(x86asm.Imm)
				if ok1 && ok2 && sameReg(a0.Base, greg) && a1 == 0 {
					curL = uint64(a0.Disp)
					return glref, curL, nil
				}
				// If Greg is dest error
				if r0, ok := i.Args[0].(x86asm.Reg); ok && sameReg(r0, greg) {
					err = errors.New("parse error, register holding G was clobbered")
					return 0, 0, err
				}
			}
		}
		b = b[i.Len:]
	}
	return 0, 0, errors.New("offsets not found")
}

// This is different in most builds and we need to get it from stripped binaries.
// The public symbol luaopen_jit gives is the best way in.  The first or second
// thing it calls is lj_dispatch_update.  We can determine which because the first
// arg is G which will come from the glref offset from L.  Ie:
//
//	0x000000000006a737 <+119>:   mov    0x10(%rbx),%rdi
//	0x000000000006a73b <+123>:   call   0x16cf0
//
// Then we load the function 0x16cf0 and look where the rdi register is stashed,
// usually rdx and then look for the first lea of rdx, ie:
//
// libluajit-5.1.so[0x16d4e] <+94>:  leaq   0xfa8(%rdx), %r10
//
// 0xfa8 is the g to dispatch offset.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_dispatch.c#L122
func (x *x86Extractor) findG2DispatchOffsetFromLjDispatchUpdate(b []byte) (uint64, error) {
	b, _ = skipEndBranch(b)
	var greg x86asm.Reg
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		// Early on we stash rdi (g) in a register
		if i.Op == x86asm.MOV {
			a0, ok1 := i.Args[0].(x86asm.Reg)
			a1, ok2 := i.Args[1].(x86asm.Reg)
			if ok1 && ok2 && a1 == x86asm.RDI {
				greg = a0
			}
		}
		// Then load dispatch address relative to g
		if i.Op == x86asm.LEA {
			a1, ok := i.Args[1].(x86asm.Mem)
			if ok && a1.Base == greg {
				return uint64(a1.Disp), nil
			}
		}
		b = b[i.Len:]
	}
	return 0, nil
}

// Find first or second call address, the one whose first argument is 0x10 off of
// sym's first argument.
// libluajit-5.1.so`luaopen_jit:
// libluajit-5.1.so[0x64dd0] <+0>:   pushq  %rbp
// libluajit-5.1.so[0x64dd1] <+1>:   pushq  %rbx
// libluajit-5.1.so[0x64dd2] <+2>:   movq   %rdi, %rbx
// libluajit-5.1.so[0x64dd5] <+5>:   xorl   %edi, %edi
// libluajit-5.1.so[0x64dd7] <+7>:   subq   $0x38, %rsp
// libluajit-5.1.so[0x64ddb] <+11>:  movq   %rsp, %rsi
// libluajit-5.1.so[0x64dde] <+14>:  callq  0xd3b6         ; lj_vm_cpuid
// libluajit-5.1.so[0x64de3] <+19>:  testl  %eax, %eax
// libluajit-5.1.so[0x64de5] <+21>:  jne    0x64f18        ; <+328> [inlined] jit_cpudetect at lib_jit.c:677:33
// libluajit-5.1.so[0x64deb] <+27>:  movl   $0x3ff0001, %eax ; imm = 0x3FF0001
// libluajit-5.1.so[0x64df0] <+32>:  movq   0x10(%rbx), %rdx
// libluajit-5.1.so[0x64df4] <+36>:  movdqa 0x7e24(%rip), %xmm0 ; jit_param_default
// libluajit-5.1.so[0x64dfc] <+44>:  movdqa 0x7e2c(%rip), %xmm1 ; jit_param_default + 16
// libluajit-5.1.so[0x64e04] <+52>:  movdqa 0x7e34(%rip), %xmm2 ; jit_param_default + 32
// libluajit-5.1.so[0x64e0c] <+60>:  movups %xmm0, 0x910(%rdx)
// libluajit-5.1.so[0x64e13] <+67>:  movups %xmm1, 0x920(%rdx)
// libluajit-5.1.so[0x64e1a] <+74>:  movups %xmm2, 0x930(%rdx)
// libluajit-5.1.so[0x64e21] <+81>:  movl   %eax, 0x350(%rdx)
// libluajit-5.1.so[0x64e27] <+87>:  leaq   0x910(%rdx), %rax
// libluajit-5.1.so[0x64e2e] <+94>:  movq   0x7e1b(%rip), %rdx ; jit_param_default + 48
// libluajit-5.1.so[0x64e35] <+101>: movq   %rdx, 0x30(%rax)
// libluajit-5.1.so[0x64e39] <+105>: movl   0x7e19(%rip), %edx ; jit_param_default + 56
// libluajit-5.1.so[0x64e3f] <+111>: movl   %edx, 0x38(%rax)
// libluajit-5.1.so[0x64e42] <+114>: movq   0x10(%rbx), %rdi
// libluajit-5.1.so[0x64e46] <+118>: callq  0x15c90        ; lj_dispatch_update at lj_dispatch.c:109:53
//
//nolint:lll
func (x *x86Extractor) findLjDispatchUpdateAddr(b []byte, addr uint64) (uint64, error) {
	b, ip := skipEndBranch(b)
	var Lreg x86asm.Reg
	rdiHasG := false
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.MOV {
			if a1, ok1 := i.Args[1].(x86asm.Reg); ok1 && a1 == x86asm.RDI {
				if a0, ok0 := i.Args[0].(x86asm.Reg); ok0 {
					Lreg = a0
				}
			}
			if a0, ok := i.Args[0].(x86asm.Reg); ok && a0 == x86asm.RDI {
				if a1, ok1 := i.Args[1].(x86asm.Mem); ok1 {
					// Look for: movq   0x10(%rbx), %rdi
					if a1.Base == Lreg && a1.Disp == 0x10 {
						rdiHasG = true
					}
				}
			}
		}

		if i.Op == x86asm.CALL && rdiHasG {
			offset := int64(i.Args[0].(x86asm.Rel))
			callAddr := int64(addr) + ip + offset + int64(i.Len)
			// TODO: make sure callAddr is within .text bounds?
			if callAddr < 0 {
				return 0, errors.New("invalid call address")
			}
			return uint64(callAddr), nil
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return 0, errors.New("lj_dispatch_update addr not found")
}

// libluajit-5.1.so`jit_checktrace:
// libluajit-5.1.so[0x63780] <+0>:  pushq  %rbx
// libluajit-5.1.so[0x63781] <+1>:  movl   $0x1, %esi
// libluajit-5.1.so[0x63786] <+6>:  movq   %rdi, %rbx
// libluajit-5.1.so[0x63789] <+9>:  callq  0x58550        ; lj_lib_checkint at lj_lib.c:239:1
// libluajit-5.1.so[0x6378e] <+14>: xorl   %r8d, %r8d
// libluajit-5.1.so[0x63791] <+17>: testl  %eax, %eax
// libluajit-5.1.so[0x63793] <+19>: je     0x637ae        ; <+46> at lib_jit.c:304:1
// libluajit-5.1.so[0x63795] <+21>: movq   0x10(%rbx), %rdx
// libluajit-5.1.so[0x63799] <+25>: cmpl   %eax, 0x43c(%rdx)
// libluajit-5.1.so[0x6379f] <+31>: jbe    0x637ae        ; <+46> at lib_jit.c:304:1
// ----------- 0x430 is the G to J->traces offset
// libluajit-5.1.so[0x637a1] <+33>: movq   0x430(%rdx), %rdx
func (x *x86Extractor) findG2TracesOffsetFromChecktrace(b []byte) (uint64, error) {
	b, _ = skipEndBranch(b)
	var Greg x86asm.Reg
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.MOV {
			a1, ok := i.Args[1].(x86asm.Mem)
			if ok {
				// glref offset is 0x10
				if a1.Disp == 0x10 {
					Greg = i.Args[0].(x86asm.Reg)
				} else if a1.Base == Greg {
					return uint64(a1.Disp), nil
				}
			}
		}
		b = b[i.Len:]
	}
	return 0, errors.New("offset not found")
}

func (x *x86Extractor) findFirstCall(b []byte, baseAddr int64) (uint64, error) {
	b, ip := skipEndBranch(b)
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.CALL {
			a0, ok := i.Args[0].(x86asm.Rel)
			if ok {
				// RIP relative calls are relative to next instruction.
				callAddr := baseAddr + ip + int64(i.Len) + int64(a0)
				return uint64(callAddr), nil
			}
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return 0, errors.New("no call found")
}

// Return true if the code in b calls targetCall.
func (x *x86Extractor) callExists(b []byte, baseAddr, targetCall int64) (bool, error) {
	b, ip := skipEndBranch(b)
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return false, err
		}
		if i.Op == x86asm.CALL {
			a0, ok := i.Args[0].(x86asm.Rel)
			if ok {
				// RIP relative calls are relative to next instruction.
				callAddr := baseAddr + ip + int64(i.Len) + int64(a0)
				if callAddr == targetCall {
					return true, nil
				}
			}
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return false, nil
}

// luaopen_jit_util will have two of these when lj_lib_prereg is inlined.
// Return the address stored in rsi for the 2nd one.
// 15457:	48 8d 35 12 67 ff ff 	lea    -0x98ee(%rip),%rsi        # bb70 <x64_init_random_constructor@@Base+0x44d0>
// 1545e:	e8 cd 1e 09 00       	call   a7330 <lua_pushcclosure@@Base>
//
//nolint:lll
func findRipRelativeLea2ndArgTo2ndCall(b []byte, baseAddr, targetCall int64) (uint64, error) {
	var leaRsi int64
	calls := 2
	b, ip := skipEndBranch(b)
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.LEA {
			a0, ok1 := i.Args[0].(x86asm.Reg)
			a1, ok2 := i.Args[1].(x86asm.Mem)
			if ok1 && ok2 {
				if a0 == x86asm.RSI && a1.Base == x86asm.RIP {
					leaRsi = calcRipRelativeAddr(a1, baseAddr, ip+int64(i.Len))
				}
			}
		}
		if i.Op == x86asm.CALL {
			a0, ok := i.Args[0].(x86asm.Rel)
			if ok {
				callAddr := baseAddr + ip + int64(i.Len) + int64(a0)
				if callAddr == targetCall {
					calls--
					if calls == 0 {
						return uint64(leaRsi), nil
					}
				}
			}
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return 0, errors.New("failed to find rip relative lea instruction stored in rsi")
}

// This function finds the IP relative value passed to lj_lib_prereg as arg 3 (rdx).
// There are 4 of these, we want the first 3rd one.
// lj_lib_prereg(L, LUA_JITLIBNAME ".util", luaopen_jit_util, tabref(L->env));
// 6d965:	48 8b 4b 48          	mov    0x48(%rbx),%rcx
// 6d969:	48 89 df             	mov    %rbx,%rdi
// 6d96c:	48 8d 15 ed e2 ff ff 	lea    -0x1d13(%rip),%rdx    # 6bc60 <luaopen_jit_util>
// 6d973:	48 8d 35 1c a2 00 00 	lea    0xa21c(%rip),%rsi     # 77b96 <lj_lib_init_debug+0x236>
// 6d97a:	e8 a1 28 ff ff       	call   60220 <lj_lib_prereg>
func (x *x86Extractor) find3rdArgToLibPreregCall(b []byte, baseAddr int64) (uint64, error) {
	var leaRdx int64
	hits := 3
	b, ip := skipEndBranch(b)
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.LEA {
			a0, ok1 := i.Args[0].(x86asm.Reg)
			a1, ok2 := i.Args[1].(x86asm.Mem)
			if ok1 && ok2 {
				if a0 == x86asm.RDX && a1.Base == x86asm.RIP {
					leaRdx = calcRipRelativeAddr(a1, baseAddr, ip+int64(i.Len))
					hits--
					if hits == 0 {
						return uint64(leaRdx), nil
					}
				}
			}
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return 0, errors.New("failed to find 3rd arg to lj_lib_prereg call")
}

// The 4th arg is pointer to function array lj_lib_cf_jit_util
// https://github.com/openresty/luajit2/blob/7952882d/src/lib_jit.c#L486
// bba0:	48 83 ec 08          	sub    $0x8,%rsp
// bba4:	48 8d 0d 55 66 0c 00 	lea    0xc6655(%rip),%rcx        # d2200 <_fini@@Base+0x195aa>
// bbab:	48 8d 15 4e dc 0a 00 	lea    0xadc4e(%rip),%rdx        # b9800 <_fini@@Base+0xbaa>
// bbb2:	31 f6                	xor    %esi,%esi
// bbb4:	e8 47 55 02 00       	call   31100 <luaL_register@@Base+0x10>
// bbb9:	b8 01 00 00 00       	mov    $0x1,%eax
// bbbe:	48 83 c4 08          	add    $0x8,%rsp
// bbc2:	c3                   	ret
func (x *x86Extractor) find4thArgToLibRegCall(b []byte, baseAddr int64) (int64, error) {
	var ip int64
	b, ip = skipEndBranch(b)
	for len(b) > 0 {
		i, err := x86asm.Decode(b, 64)
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.LEA {
			a0, ok1 := i.Args[0].(x86asm.Reg)
			a1, ok2 := i.Args[1].(x86asm.Mem)
			if ok1 && ok2 {
				// RCX is 4th arg
				if a0 == x86asm.RCX && a1.Base == x86asm.RIP {
					return calcRipRelativeAddr(a1, baseAddr, ip+int64(i.Len)), nil
				}
			}
		}
		ip += int64(i.Len)
		b = b[i.Len:]
	}
	return 0, errors.New("failed to find 4th arg to lj_reg call")
}

func calcRipRelativeAddr(a1 x86asm.Mem, baseAddr, ip int64) int64 {
	// Disp is an int64 but its not set properly and negative numbers
	// are 32 bit.  TODO: This is a bug that should be created/looked up.
	disp := int32(a1.Disp)
	return baseAddr + ip + int64(disp)
}

var endbr64 = [4]byte{0xf3, 0x0f, 0x1e, 0xfa}

// On some binaries the function starts like this:
//
//	0x0000000000012860 <+0>:     f3 0f 1e fa     endbr64
//	0x0000000000012864 <+4>:     41 55   push   %r13
//
// This is some kind of stack smashing indirect jump protection, treat it as a nop,
// x86asm doesn't know how to handle it.
//
//nolint:gocritic
func skipEndBranch(b []byte) ([]byte, int64) {
	if slices.Equal(b[0:4], endbr64[:]) {
		return b[4:], 4
	}
	return b, 0
}

// If we're dealing with 32bit values compilers will use R or E prefix
// interchangeably (E refs are just zero padded).
func sameReg(r1, r2 x86asm.Reg) bool {
	if r1 == r2 {
		return true
	}
	f := func(r1, r2 x86asm.Reg) bool {
		switch r1 {
		case x86asm.EAX:
			return r2 == x86asm.RAX
		case x86asm.ECX:
			return r2 == x86asm.RCX
		case x86asm.EDX:
			return r2 == x86asm.RDX
		case x86asm.EBX:
			return r2 == x86asm.RBX
		default:
			return false
		}
	}
	return f(r1, r2) || f(r2, r1)
}
