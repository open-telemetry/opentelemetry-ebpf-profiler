// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
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
// findOffsetsFromLuaClose recovers glref (offset of G in L) and curL (offset of
// cur_L in G) from lua_close. The prologue looks like:
//
//	mov 0x10(%rdi), %rbx       ; %rbx = L->glref  (i.e. G)
//	...
//	mov %rsi, 0x158(%rbx)      ; G->cur_L = 0  (%rsi previously zeroed via XOR)
//
// We drive the asm/amd symbolic interpreter so that whichever register ends up
// holding G keeps its provenance (Mem8([L + glref])) regardless of MOV chains,
// 32/64-bit register aliasing, or which register the compiler picks. We then
// stop at the first memory store of zero whose base register matches that
// expression and read both offsets off it.
//
//nolint:nonamedreturns
func (x *x86Extractor) findOffsetsFromLuaClose(b []byte) (glref, curL uint64, err error) {
	it := amd.NewInterpreterWithCode(b)
	// SysV ABI passes lua_State *L in RDI. The interpreter initializes every
	// register to a fresh Named expression, so RDI's initial value IS our L.
	// expression.Match uses pointer equality for *named, so this same instance
	// is what we'll match against.
	L := it.Regs.GetX86(x86asm.RDI)

	for {
		inst, stepErr := it.Step()
		if stepErr != nil {
			if errors.Is(stepErr, io.EOF) {
				break
			}
			return 0, 0, fmt.Errorf("scanning lua_close for glref store: %w", stepErr)
		}
		if inst.Op != x86asm.MOV {
			continue
		}
		dst, isMem := inst.Args[0].(x86asm.Mem)
		if !isMem || dst.Base == 0 {
			continue
		}
		if !isZeroOperand(inst.Args[1], &it.Regs) {
			continue
		}
		// The interpreter doesn't model memory stores, so the symbolic value of
		// the destination's base register is its value as of just before the
		// store - exactly what we want. We expect G = Mem8([L + glref]).
		glrefCap := expression.NewImmediateCapture("glref")
		if it.Regs.GetX86(dst.Base).Match(
			expression.Mem8(expression.Add(L, glrefCap)),
		) {
			return glrefCap.CapturedValue(), uint64(dst.Disp), nil
		}
	}
	return 0, 0, errors.New("find offsets from lua_close failed")
}

// isZeroOperand reports whether arg currently evaluates to zero - either as a
// literal immediate or as a register the symbolic interpreter has determined
// holds zero (typically from xor reg, reg).
func isZeroOperand(arg x86asm.Arg, regs *amd.Registers) bool {
	switch v := arg.(type) {
	case x86asm.Imm:
		return v == 0
	case x86asm.Reg:
		cap := expression.NewImmediateCapture("zero")
		return regs.GetX86(v).Match(cap) && cap.CapturedValue() == 0
	}
	return false
}

// This is different in most builds and we need to get it from stripped binaries.
// The public symbol luaopen_jit is the best way in. The first or second
// thing it calls is lj_dispatch_update. We can determine which because the first
// arg is G which will come from the glref offset from L.  Ie:
//
//	0x000000000006a737 <+119>:   mov    0x10(%rbx),%rdi
//	0x000000000006a73b <+123>:   call   0x16cf0
//
// Then we load the function 0x16cf0 and look at how it fills the per-G dispatch
// table. lj_dispatch_update emits an init loop bounded by two `lea OFS(%greg), %reg`
// instructions whose displacements are the start and end of the dispatch table.
// The smaller of the two displacements is normally the value we want. The
// compiler is free to emit the bounds in either order, and in some builds the
// very first slot of the dispatch table is peeled off into a pre-loop
// `mov %X, OFS(%greg)` store - in that case OFS sits a slot below the loop iter
// LEA and that store's displacement is the canonical g2dispatch.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_dispatch.c#L122
func (x *x86Extractor) findG2DispatchOffsetFromLjDispatchUpdate(b []byte) (uint64, error) {
	type ref struct {
		disp int64
		pos  int
	}
	var (
		greg   x86asm.Reg
		leas   []ref
		stores []ref
	)

	it := amd.NewInterpreterWithCode(b)
	for {
		i, err := it.Step()
		if err != nil {
			// Some builds put SSE/AVX instructions the decoder doesn't know
			// later in lj_dispatch_update; stop scanning and decide from what
			// we have so far rather than failing the whole load.
			break
		}
		// The dispatch table init lives in the prologue; once we hit a call
		// we've left the region we care about.
		if i.Op == x86asm.CALL {
			break
		}
		if i.Op == x86asm.MOV {
			// Early on we stash rdi (g) in a register.
			if dst, dstOk := i.Args[0].(x86asm.Reg); dstOk {
				if src, srcOk := i.Args[1].(x86asm.Reg); srcOk && src == x86asm.RDI {
					greg = dst
				}
			}
			// `mov %src, OFS(%greg)` - a peeled-off pre-loop store. Capture it
			// so we can spot a dispatch-table first-slot store sitting one slot
			// below the loop iter LEA.
			if dst, ok := i.Args[0].(x86asm.Mem); ok && greg != 0 &&
				dst.Base == greg && dst.Index == 0 && dst.Disp > 0 {
				stores = append(stores, ref{disp: dst.Disp, pos: it.PC()})
			}
		}
		if i.Op == x86asm.LEA && greg != 0 {
			if src, ok := i.Args[1].(x86asm.Mem); ok && src.Base == greg &&
				src.Index == 0 && src.Disp > 0 {
				leas = append(leas, ref{disp: src.Disp, pos: it.PC()})
			}
		}
	}

	if len(leas) == 0 {
		return 0, nil
	}
	if len(leas) == 1 {
		return uint64(leas[0].disp), nil
	}

	// Look for a pair of LEAs off greg whose displacements differ by no more
	// than the dispatch table size (a few hundred bytes in every observed
	// build).  Those are the bounds of the dispatch fill loop; the smaller
	// disp is the loop iter start.
	const maxDispatchTable = 1024
	for i := 0; i < len(leas); i++ {
		for j := i + 1; j < len(leas); j++ {
			small := min(leas[i].disp, leas[j].disp)
			big := max(leas[i].disp, leas[j].disp)
			if big-small > maxDispatchTable {
				continue
			}
			firstPos := min(leas[i].pos, leas[j].pos)
			best := small
			// If a slot just below the loop iter was filled by a peeled-off
			// pre-loop store, prefer its displacement - that's the slot the
			// DISPATCH register actually points at in JIT code.
			for _, s := range stores {
				if s.pos < firstPos && s.disp < small && small-s.disp <= 16 &&
					s.disp < best {
					best = s.disp
				}
			}
			return uint64(best), nil
		}
	}

	// No recognizable loop pair - fall back to the first LEA, matching the
	// historical heuristic.
	return uint64(leas[0].disp), nil
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
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(addr)
	// L is initial RDI (SysV first arg). lj_dispatch_update's first arg is G,
	// reached via L->glref at offset 0x10. We don't care which register the
	// compiler parks L in - symbolic tracking handles the chain.
	L := it.Regs.GetX86(x86asm.RDI)
	G := expression.Mem8(expression.Add(L, expression.Imm(0x10)))

	for {
		inst, err := it.Step()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("scanning function body: %w", err)
		}
		if inst.Op != x86asm.CALL {
			continue
		}
		if !it.Regs.GetX86(x86asm.RDI).Match(G) {
			continue
		}
		rel, ok := inst.Args[0].(x86asm.Rel)
		if !ok {
			continue
		}
		// it.PC() is the offset past the CALL within the interpreter's bytes,
		// which equals the offset in the caller's bytes since we started at 0.
		callAddr := int64(addr) + int64(it.PC()) + int64(rel)
		if callAddr < 0 {
			return 0, errors.New("invalid call address")
		}
		return uint64(callAddr), nil
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
//
// Some builds apply an ADD/SUB constant to the register holding G before the
// final load; the symbolic interpreter folds those into the address expression
// for free, so the captured displacement is the true G->traces offset.
func (x *x86Extractor) findG2TracesOffsetFromChecktrace(b []byte) (uint64, error) {
	it := amd.NewInterpreterWithCode(b)
	// L is initial RDI; G is L->glref. glref is hard-wired at 0x10 in the
	// LJ_GC64 layout (findOffsetsFromLuaClose enforces this assumption
	// before extractOffsets gets here).
	L := it.Regs.GetX86(x86asm.RDI)
	G := expression.Mem8(expression.Add(L, expression.Imm(0x10)))
	tracesCap := expression.NewImmediateCapture("g2traces")
	pattern := expression.Mem8(expression.Add(G, tracesCap))

	for {
		inst, err := it.Step()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("scanning jit_checktrace for G->traces load: %w", err)
		}
		// We're looking for a load from [G + disp] into a register; the
		// destination's new symbolic value is what we match against.
		if inst.Op != x86asm.MOV {
			continue
		}
		dstReg, dstIsReg := inst.Args[0].(x86asm.Reg)
		if !dstIsReg {
			continue
		}
		if _, srcIsMem := inst.Args[1].(x86asm.Mem); !srcIsMem {
			continue
		}
		if it.Regs.GetX86(dstReg).Match(pattern) {
			return tracesCap.CapturedValue(), nil
		}
	}
	return 0, errors.New("offset not found")
}

func (x *x86Extractor) findFirstCall(b []byte, baseAddr int64) (uint64, error) {
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(uint64(baseAddr))
	for {
		i, err := it.Step()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		if i.Op == x86asm.CALL {
			a0, ok := i.Args[0].(x86asm.Rel)
			if ok {
				callAddr := baseAddr + int64(it.PC()) + int64(a0)
				return uint64(callAddr), nil
			}
		}
	}
	return 0, errors.New("no call found")
}

// Return true if the code in b calls targetCall.
func (x *x86Extractor) callExists(b []byte, baseAddr, targetCall int64) (bool, error) {
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(uint64(baseAddr))
	for {
		i, err := it.Step()

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, err
		}
		if i.Op == x86asm.CALL {
			a0, ok := i.Args[0].(x86asm.Rel)
			if ok {
				callAddr := baseAddr + int64(it.PC()) + int64(a0)
				if callAddr == targetCall {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// luaopen_jit will have two of these when lj_lib_prereg is inlined.
// Return the address stored in rsi for the 2nd one.
// 15457:	48 8d 35 12 67 ff ff 	lea    -0x98ee(%rip),%rsi        # bb70 <x64_init_random_constructor@@Base+0x44d0>
// 1545e:	e8 cd 1e 09 00       	call   a7330 <lua_pushcclosure@@Base>
//
//nolint:lll
func (x *x86Extractor) find2ndArgTo2ndPushClosureCall(b []byte, baseAddr, targetCall int64) (uint64, error) {
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(uint64(baseAddr))
	callsLeft := 2

	for {
		inst, err := it.Step()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("scanning function body: %w", err)
		}
		if inst.Op != x86asm.CALL {
			continue
		}
		rel, ok := inst.Args[0].(x86asm.Rel)
		if !ok {
			continue
		}
		if baseAddr+int64(it.PC())+int64(rel) != targetCall {
			continue
		}
		callsLeft--
		if callsLeft > 0 {
			continue
		}
		// Each LEA $disp(%rip), %rsi the interpreter has executed sets RSI to
		// a concrete absolute address (CodeAddress + pc_after_lea + disp).
		// Read whatever RSI currently holds; if the immediate-preceding LEA
		// canonicalized to an Imm it will match.
		rsiCap := expression.NewImmediateCapture("rsi")
		if !it.Regs.GetX86(x86asm.RSI).Match(rsiCap) {
			return 0, errors.New("RSI is not a concrete address at the 2nd matching call")
		}
		return rsiCap.CapturedValue(), nil
	}
	return 0, errors.New("failed to find rip relative lea instruction stored in rsi")
}

//nolint:gocritic
func skipCallsAABA(it *amd.Interpreter, baseAddr int64) error {
	var lastCall int64
	var acall int64
	// 3 Step process, 1 is find AA, 2 is find B and 3 is find A.
	step := 0

	for {
		i, err := it.LoopWithBreak(func(i x86asm.Inst) bool {
			return i.Op == x86asm.CALL
		})
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("skipping AABA: %w", err)
		}
		a0, ok := i.Args[0].(x86asm.Rel)
		if ok {
			callAddr := baseAddr + int64(it.PC()) + int64(a0)
			if step == 0 && callAddr == lastCall {
				// Found potential AA
				step = 1
				acall = callAddr
			} else if step == 1 && callAddr != lastCall {
				// Found AAB
				step = 2
			} else if step == 2 && callAddr == acall {
				// Found AABA
				step = 3
			} else {
				// Found different pattern, reset
				step = 0
				acall = 0
			}
			lastCall = callAddr
		}
		if step == 3 {
			return nil
		}

	}
	return errors.New("failed to find AABA call pattern")
}

// This function finds the IP relative value passed to lj_lib_prereg as arg 3 (rdx).
// There are 4 of these, we want the 3rd one.
// lj_lib_prereg(L, LUA_JITLIBNAME ".util", luaopen_jit_util, tabref(L->env));
// 6d965:	48 8b 4b 48          	mov    0x48(%rbx),%rcx
// 6d969:	48 89 df             	mov    %rbx,%rdi
// 6d96c:	48 8d 15 ed e2 ff ff 	lea    -0x1d13(%rip),%rdx    # 6bc60 <luaopen_jit_util>
// 6d973:	48 8d 35 1c a2 00 00 	lea    0xa21c(%rip),%rsi     # 77b96 <lj_lib_init_debug+0x236>
// 6d97a:	e8 a1 28 ff ff       	call   60220 <lj_lib_prereg>
func (x *x86Extractor) find3rdArgToLibPreregCall(b []byte, baseAddr int64) (uint64, error) {
	// Skip the lua_push* call sequence (and all the preceding calls which varies depending on
	// inlining).
	// libluajit-5.1.so[0x700a5] <+133>: movq   %rbx, %rdi
	// libluajit-5.1.so[0x700a8] <+136>: movl   $0x5, %edx
	// libluajit-5.1.so[0x700ad] <+141>: leaq   0x9b35(%rip), %rsi
	// libluajit-5.1.so[0x700b4] <+148>: callq  0x9af0         ; symbol stub for: lua_pushlstring
	// libluajit-5.1.so[0x700b9] <+153>: movl   $0x3, %edx
	// libluajit-5.1.so[0x700be] <+158>: movq   %rbx, %rdi
	// libluajit-5.1.so[0x700c1] <+161>: leaq   0x9b27(%rip), %rsi
	// libluajit-5.1.so[0x700c8] <+168>: callq  0x9af0         ; symbol stub for: lua_pushlstring
	// libluajit-5.1.so[0x700cd] <+173>: movq   %rbx, %rdi
	// libluajit-5.1.so[0x700d0] <+176>: movl   $0x4ee7, %esi ; imm = 0x4EE7
	// libluajit-5.1.so[0x700d5] <+181>: callq  0x9360         ; symbol stub for: lua_pushinteger
	// libluajit-5.1.so[0x700da] <+186>: movq   %rbx, %rdi
	// libluajit-5.1.so[0x700dd] <+189>: movl   $0x12, %edx
	// libluajit-5.1.so[0x700e2] <+194>: leaq   0x9b0a(%rip), %rsi
	// libluajit-5.1.so[0x700e9] <+201>: callq  0x9af0         ; symbol stub for: lua_pushlstring
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(uint64(baseAddr))
	err := skipCallsAABA(it, baseAddr)
	if err != nil {
		return 0, err
	}
	callsLeft := 3

	for {
		inst, err := it.Step()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("scanning function body: %w", err)
		}
		if inst.Op != x86asm.CALL {
			continue
		}
		callsLeft--
		if callsLeft > 0 {
			continue
		}
		// At the 3rd call after AABA, RDX should hold the luaopen_jit_util
		// address - either via `lea $rip-rel, %rdx` (canonicalized to a
		// concrete Imm by the interpreter) or `mov $imm, %edx` (some
		// compilers).
		rdxCap := expression.NewImmediateCapture("rdx")
		if !it.Regs.GetX86(x86asm.RDX).Match(rdxCap) {
			return 0, errors.New("RDX is not a concrete value at the 3rd post-AABA call")
		}
		return rdxCap.CapturedValue(), nil
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
	it := amd.NewInterpreterWithCode(b)
	it.CodeAddress = expression.Imm(uint64(baseAddr))
	// luaopen_jit_util's body is: set up call args (RCX via either
	// `lea $rip-rel, %rcx` or `mov $imm, %ecx`), then call lj_lib_register.
	// Step until that CALL, then read RCX symbolically.
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.CALL
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	rcxCap := expression.NewImmediateCapture("rcx")
	if !it.Regs.GetX86(x86asm.RCX).Match(rcxCap) {
		return 0, errors.New("failed to find 4th arg to lj_reg call")
	}
	return int64(rcxCap.CapturedValue()), nil
}
