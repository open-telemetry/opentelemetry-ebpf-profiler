// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// ELF files with personality function used (C++) and .debug_frame sections
// can have a large amount of CIEs. Typically they are used in localized
// manner, but in some cases there can be back references to deep in
// the history. This should allow caching most of the CIEs.
const cieCacheSize = 128

// errUnexpectedType is used internally to detect inconsistent FDE/CIE types
var errUnexpectedType = errors.New("unexpected FDE/CIE type")

// errEmptyEntry is used internally to report FDEs/CIEs of length 0.
var errEmptyEntry = errors.New("FDE/CIE empty")

// ehframeHooks interface provides hooks for filtering and debugging eh_frame parsing
type ehframeHooks interface {
	// fdeHook is called for each FDE. Returns false if the FDE should be filtered out.
	fdeHook(cie *cieInfo, fde *fdeInfo) bool
	// deltaHook is called for each stack delta found
	deltaHook(ip uintptr, regs *vmRegs, info sdtypes.UnwindInfo)
	// golangHook is called if .gopclntab is found to report its coverage
	golangHook(start, end uintptr)
}

// uleb128 is the data type for unsigned little endian base-128 encoded number
type uleb128 uint64

// sleb128 is the data type for signed little endian base-128 encoded number
type sleb128 int64

// DWARF Call Frame Instructions
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.2
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
type cfaOpcode uint8

const (
	cfaNop                  cfaOpcode = 0x00
	cfaSetLoc               cfaOpcode = 0x01
	cfaAdvanceLoc1          cfaOpcode = 0x02
	cfaAdvanceLoc2          cfaOpcode = 0x03
	cfaAdvanceLoc4          cfaOpcode = 0x04
	cfaOffsetExtended       cfaOpcode = 0x05
	cfaRestoreExtended      cfaOpcode = 0x06
	cfaUndefined            cfaOpcode = 0x07
	cfaSameValue            cfaOpcode = 0x08
	cfaRegister             cfaOpcode = 0x09
	cfaRememberState        cfaOpcode = 0x0a
	cfaRestoreState         cfaOpcode = 0x0b
	cfaDefCfa               cfaOpcode = 0x0c
	cfaDefCfaRegister       cfaOpcode = 0x0d
	cfaDefCfaOffset         cfaOpcode = 0x0e
	cfaDefCfaExpression     cfaOpcode = 0x0f
	cfaExpression           cfaOpcode = 0x10
	cfaOffsetExtendedSf     cfaOpcode = 0x11
	cfaDefCfaSf             cfaOpcode = 0x12
	cfaDefCfaOffsetSf       cfaOpcode = 0x13
	cfaValOffset            cfaOpcode = 0x14
	cfaValOffsetSf          cfaOpcode = 0x15
	cfaValExpression        cfaOpcode = 0x16
	cfaGNUWindowSave        cfaOpcode = 0x2d
	cfaGNUArgsSize          cfaOpcode = 0x2e
	cfaGNUNegOffsetExtended cfaOpcode = 0x2f
	cfaAdvanceLoc           cfaOpcode = 0x40
	cfaOffset               cfaOpcode = 0x80
	cfaRestore              cfaOpcode = 0xc0
	cfaHighOpcodeMask       cfaOpcode = 0xc0
	cfaHighOpcodeValueMask  cfaOpcode = 0x3f
)

// DWARF Expression Opcodes
// http://dwarfstd.org/doc/DWARF5.pdf §2.5, §7.7.1
// The subset needed for normal .eh_frame handling
type expressionOpcode uint8

const (
	opDeref      expressionOpcode = 0x06
	opConstU     expressionOpcode = 0x10
	opConstS     expressionOpcode = 0x11
	opRot        expressionOpcode = 0x17
	opAnd        expressionOpcode = 0x1a
	opMul        expressionOpcode = 0x1e
	opPlus       expressionOpcode = 0x22
	opPlusUConst expressionOpcode = 0x23
	opShl        expressionOpcode = 0x24
	opGE         expressionOpcode = 0x2a
	opNE         expressionOpcode = 0x2e
	opLit0       expressionOpcode = 0x30
	opBReg0      expressionOpcode = 0x70
)

type dwarfExpression struct {
	opcode   expressionOpcode
	operand1 uleb128
	operand2 uleb128
}

// DWARF Exception Header Encoding
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
type encoding uint8

const (
	encFormatNative  encoding = 0x00
	encFormatLeb128  encoding = 0x01
	encFormatData2   encoding = 0x02
	encFormatData4   encoding = 0x03
	encFormatData8   encoding = 0x04
	encFormatMask    encoding = 0x07
	encSignedMask    encoding = 0x08
	encAdjustAbs     encoding = 0x00
	encAdjustPcRel   encoding = 0x10
	encAdjustTextRel encoding = 0x20
	encAdjustDataRel encoding = 0x30
	encAdjustFuncRel encoding = 0x40
	encAdjustAligned encoding = 0x50
	encAdjustMask    encoding = 0x70
	encIndirect      encoding = 0x80
	encOmit          encoding = 0xff
)

// Exception Frame Header (.eh_frame_hdr section)
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
type ehFrameHdr struct {
	version       uint8
	ehFramePtrEnc encoding
	fdeCountEnc   encoding
	tableEnc      encoding
	// Continued with the following:
	// ehFramePtr    ptr{ehFramePtrEnc}
	// fdeCount      ptr{fdeCountEnc}
	// searchTable   [fdeCount]struct {
	//	startIp ptr{tableEnc}
	//	fdeAddr ptr{tableEnc}
	// }
}

// reader provides read access to the Exception Frame section and the virtual address base.
type reader struct {
	*pfbufio.Reader

	machine    elf.Machine
	debugFrame bool
	vaddr      uint64
}

// uleb reads one unsigned little endian base-128 encoded value
func (r *reader) uleb() uleb128 {
	b := uint8(0x80)
	val := uleb128(0)
	for shift := 0; b&0x80 != 0; shift += 7 {
		b = r.Uint8()
		val |= uleb128(b&0x7f) << shift
	}
	return val
}

// sleb reads one signed little endian base-128 encoded value
func (r *reader) sleb() sleb128 {
	b := uint8(0x80)
	val := sleb128(0)
	shift := 0
	for ; b&0x80 != 0; shift += 7 {
		b = r.Uint8()
		val |= sleb128(b&0x7f) << shift
	}
	if b&0x40 != 0 {
		// Sign extend
		val |= sleb128(-1) << shift
	}
	return val
}

// expression reads one DWARF expression, and normalizes it in the sense that
// opcodes are returned in indexable slice and each opcode with operand is
// adjusted to it's basic value with operand separated. The concept is to allow
// pattern matching expression with opcodes sequences.
func (r *reader) expression() ([]dwarfExpression, error) {
	if err := r.StartSection(int64(r.uleb())); err != nil {
		return nil, err
	}
	defer r.EndSection()

	expr := make([]dwarfExpression, 0, 8)
	for r.Remaining() > 0 {
		op := expressionOpcode(r.Uint8())
		switch {
		case op >= opLit0 && op <= opLit0+31:
			expr = append(expr, dwarfExpression{
				opcode:   opLit0,
				operand1: uleb128(op - opLit0),
			})
		case op >= opBReg0 && op <= opBReg0+31:
			expr = append(expr, dwarfExpression{
				opcode:   opBReg0,
				operand1: uleb128(op - opBReg0),
				operand2: uleb128(r.sleb()),
			})
		case op == opConstU, op == opPlusUConst:
			expr = append(expr, dwarfExpression{
				opcode:   op,
				operand1: r.uleb(),
			})
		case op == opConstS:
			expr = append(expr, dwarfExpression{
				opcode:   op,
				operand1: uleb128(r.sleb()),
			})
		case op == opDeref, op >= opRot && op <= opNE:
			expr = append(expr, dwarfExpression{opcode: op})
		default:
			return nil, fmt.Errorf("unsupported expression opcode: %x", op)
		}
	}
	return expr, nil
}

// ptr reads one pointer value encoded with enc encoding
func (r *reader) ptr(enc encoding) (uintptr, error) {
	if enc == encOmit {
		return 0, nil
	}
	var val, sz uint64
	switch enc & (encFormatMask | encSignedMask) {
	case encFormatData2:
		val = uint64(r.Uint16())
		sz = 2
	case encFormatData4:
		val = uint64(r.Uint32())
		sz = 4
	case encFormatData8, encFormatNative, encFormatData8 | encSignedMask:
		val = r.Uint64()
		sz = 8
	case encFormatData2 | encSignedMask:
		val = uint64(int64(r.Int16()))
		sz = 2
	case encFormatData4 | encSignedMask:
		val = uint64(int64(r.Int32()))
		sz = 4
	default:
		return 0, fmt.Errorf("unsupported format encoding %#02x", enc)
	}

	switch enc & encAdjustMask {
	case encAdjustAbs:
	case encAdjustPcRel:
		val += uint64(r.Tell()) - sz + r.vaddr
	case encAdjustDataRel:
		val += r.vaddr
	default:
		return 0, fmt.Errorf("unsupported adjust encoding %#02x", enc)
	}

	if enc&encIndirect != 0 {
		return 0, fmt.Errorf("unsupported indirect encoding %#02x", enc)
	}

	return uintptr(val), nil
}

// cieInfo describes the contents of one Common Information Entry (CIE)
type cieInfo struct {
	dataAlign       sleb128
	codeAlign       uleb128
	regRA           uleb128
	enc             encoding
	ldsaEnc         encoding
	hasAugmentation bool
	isSignalHandler bool

	// initialState is the virtual machine state after running CIE opcodes
	initialState vmRegs
}

// fdeInfo contains one Frame Description Entry (FDE)
type fdeInfo struct {
	id      int64
	ciePos  int64
	ipLen   uintptr
	ipStart uintptr
}

const (
	// extensions values used internally
	regUndefined       uleb128 = 128
	regCFA             uleb128 = 129
	regCFAVal          uleb128 = 130
	regSame            uleb128 = 131
	regExprPLT         uleb128 = 256
	regExprRegDeref    uleb128 = 257
	regExprRegRegDeref uleb128 = 258
	regExprReg         uleb128 = 259
)

// sigretCodeMap contains the per-machine trampoline to call rt_sigreturn syscall.
// This is needed to detect signal trampoline functions as the .eh_frame often
// does not contain the proper unwind info due to various reasons.
//
//nolint:lll
var sigretCodeMap = map[elf.Machine][]byte{
	elf.EM_AARCH64: {
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/vdso/sigreturn.S?h=v6.4#n71
		// https://git.musl-libc.org/cgit/musl/tree/src/signal/aarch64/restore.s?h=v1.2.4#n9
		// movz x8, #0x8b
		0x68, 0x11, 0x80, 0xd2,
		// svc  #0x0
		0x01, 0x00, 0x00, 0xd4,
	},
	elf.EM_X86_64: {
		// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/libc_sigaction.c;h=afdce87381228f0cf32fa9fa6c8c4efa5179065c;hb=a704fd9a133bfb10510e18702f48a6a9c88dbbd5#l80
		// https://git.musl-libc.org/cgit/musl/tree/src/signal/x86_64/restore.s?h=v1.2.4#n6
		// mov $0xf,%rax
		0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00,
		// syscall
		0x0f, 0x05,
	},
}

// vmReg describes the register unwinding state in dwarf virtual machine
type vmReg struct {
	arch elf.Machine
	// reg is the register or extension base to use
	reg uleb128
	// off is the offset to add to the base
	off sleb128
}

// makeOff encodes four 16-bit integers into vmReg.off field to be used as expression parameters
func makeOff(a, b, c, d int16) sleb128 {
	return sleb128((uleb128(uint16(a)) << 48) + (uleb128(uint16(b)) << 32) +
		(uleb128(uint16(c)) << 16) + uleb128(uint16(d)))
}

// splitOff undoes makeOff and splits the vmReg.off to 16-bit integers
func splitOff(off sleb128) (a, b, c, d int16) {
	return int16(off >> 48), int16(off >> 32), int16(off >> 16), int16(off)
}

// getCFARegName converts internally used register descriptions into a string
func getCFARegName(reg uleb128) string {
	switch reg {
	case regCFA:
		return "c"
	case regCFAVal:
		return "&c"
	case regUndefined:
		return "u"
	case regSame:
		return "s"
	default:
		return fmt.Sprintf("r%d", reg)
	}
}

// getRegName converts register index to a string describing the register
func getRegName(arch elf.Machine, reg uleb128) string {
	switch {
	case reg >= regUndefined:
		return getCFARegName(reg)
	case arch == elf.EM_AARCH64:
		return getRegNameARM(reg)
	case arch == elf.EM_X86_64:
		return getRegNameX86(reg)
	default:
		log.Errorf("Unexpected register index value: %d", reg)
		return fmt.Sprintf("unk%d", reg)
	}
}

// String will format the unwinding rule for 'reg' as a string
func (reg *vmReg) String() string {
	if reg.reg < regExprPLT {
		name := getRegName(reg.arch, reg.reg)
		if reg.off == 0 {
			return name
		}
		return fmt.Sprintf("%s%+d", name, reg.off)
	}
	switch reg.reg {
	case regExprPLT:
		return "plt"
	case regExprReg:
		a, _, b, _ := splitOff(reg.off)
		return fmt.Sprintf("%s%+d", getRegName(reg.arch, uleb128(a)), b)
	case regExprRegDeref:
		a, _, b, c := splitOff(reg.off)
		return fmt.Sprintf("*(%s%+d)%+d",
			getRegName(reg.arch, uleb128(a)), b, c)
	case regExprRegRegDeref:
		a, b, c, d := splitOff(reg.off)
		return fmt.Sprintf("*(%s+8*%s+%d)%+d",
			getRegName(reg.arch, uleb128(a)), getRegName(reg.arch, uleb128(b)), c, d)
	default:
		return "?"
	}
}

// expression recognizes the argument expression and sets the vmReg value to it
func (reg *vmReg) expression(expr []dwarfExpression) error {
	reg.reg = regUndefined
	reg.off = 0

	// Support is included for few selected expression
	switch {
	case matchExpression(expr, []expressionOpcode{
		opBReg0, opBReg0, opLit0, opAnd,
		opLit0, opGE, opLit0, opShl, opPlus,
	}):
		// Assume this sequence is the PLT expression generated by GCC,
		// regardless of the operand values
		reg.reg = regExprPLT
	case matchExpression(expr, []expressionOpcode{opBReg0}):
		// Register dereference expression (seen for registers in SSE vectorized code)
		reg.reg = regExprReg
		reg.off = makeOff(int16(expr[0].operand1), 0, int16(expr[0].operand2), 0)
	case matchExpression(expr, []expressionOpcode{opBReg0, opDeref}):
		// Register dereference expression (seen for CFA in SSE vectorized code)
		reg.reg = regExprRegDeref
		reg.off = makeOff(int16(expr[0].operand1), 0, int16(expr[0].operand2), 0)
	case matchExpression(expr, []expressionOpcode{opBReg0, opDeref, opPlusUConst}):
		// Register dereference expression (seen in openssl libcrypto)
		reg.reg = regExprRegDeref
		reg.off = makeOff(int16(expr[0].operand1), 0, int16(expr[0].operand2),
			int16(expr[2].operand1))
	case matchExpression(expr, []expressionOpcode{
		opBReg0, opBReg0, opLit0, opMul,
		opPlus, opDeref, opPlusUConst,
	}) &&
		expr[1].operand2 == 0 && expr[2].operand1 == 8:
		// Register + register dereference expression (seen in openssl libcrypto)
		reg.reg = regExprRegRegDeref
		reg.off = makeOff(
			int16(expr[0].operand1), int16(expr[1].operand1),
			int16(expr[0].operand2), int16(expr[6].operand1))
	default:
		return fmt.Errorf("DWARF expression unmatched: %x", expr)
	}
	return nil
}

// vmRegs contains the dwarf virtual machine registers we track
type vmRegs struct {
	arch elf.Machine
	cfa  vmReg
	// generic (platform independent) DWARF registers for frame pointer
	// and return address access
	fp, ra vmReg
}

// reg returns the address to vmReg description of the given numeric register
func (regs *vmRegs) reg(ndx uleb128) *vmReg {
	switch regs.arch {
	case elf.EM_AARCH64:
		return regs.regARM(ndx)
	case elf.EM_X86_64:
		return regs.regX86(ndx)
	default:
		return nil
	}
}

// state is the virtual machine state which can execute exception handler opcodes
type state struct {
	// cie is the CIE being currently processed
	cie *cieInfo
	// loc is the current location (RIP)
	loc uintptr
	// cur is the current state of the virtual machine
	cur vmRegs
	// stash is the implicit stack of register states for remember/restore opcodes
	stack [2]vmRegs
	// stackNdx is the current stack nesting level for remember/restore opcodes
	stackNdx int
}

// advance increments current virtual address by given delta and code alignment
func (st *state) advance(delta int) {
	st.loc += uintptr(delta * int(st.cie.codeAlign))
}

// rule assign an unwinding rule for given register 'reg'
func (st *state) rule(reg, baseReg uleb128, off sleb128) {
	r := st.cur.reg(reg)
	if r != nil {
		r.reg = baseReg
		r.off = off * st.cie.dataAlign
	}
}

// restore assigns given numeric register it's original value after CIE opcodes
func (st *state) restore(reg uleb128) {
	if to := st.cur.reg(reg); to != nil {
		*to = *st.cie.initialState.reg(reg)
	}
}

// matchExpression compares if the opcodes of expr match the template given
func matchExpression(expr []dwarfExpression, template []expressionOpcode) bool {
	if len(expr) != len(template) {
		return false
	}
	for i := range expr {
		if expr[i].opcode != template[i] {
			return false
		}
	}
	return true
}

// step executes the EH virtual opcodes until a new virtual address is encountered
// or end of opcodes is reached.
func (st *state) step(r *reader) error {
	var err error
	for r.Remaining() > 0 {
		opcode := cfaOpcode(r.Uint8())
		operand := uint8(0)

		// If the high opcode bits are set, the upper bits are opcode
		// and the lower bits is operand.
		if opcode&cfaHighOpcodeMask != 0 {
			operand = uint8(opcode & cfaHighOpcodeValueMask)
			opcode &= cfaHighOpcodeMask
		}

		// Handle the opcode
		switch opcode {
		case cfaNop:
			// Nothing to do!
		case cfaSetLoc:
			st.loc, err = r.ptr(st.cie.enc)
			return err
		case cfaAdvanceLoc1:
			st.advance(int(r.Uint8()))
			return nil
		case cfaAdvanceLoc2:
			st.advance(int(r.Uint16()))
			return nil
		case cfaAdvanceLoc4:
			st.advance(int(r.Uint32()))
			return nil
		case cfaOffsetExtended:
			st.rule(r.uleb(), regCFA, sleb128(r.uleb()))
		case cfaRestoreExtended:
			st.restore(r.uleb())
		case cfaUndefined:
			st.rule(r.uleb(), regUndefined, 0)
		case cfaSameValue:
			st.rule(r.uleb(), regSame, 0)
		case cfaRegister:
			st.rule(r.uleb(), r.uleb(), 0)
		case cfaRememberState:
			if st.stackNdx >= len(st.stack) {
				return fmt.Errorf("dwarf stack overflow at %x",
					st.loc)
			}
			st.stack[st.stackNdx] = st.cur
			st.stackNdx++
		case cfaRestoreState:
			if st.stackNdx == 0 {
				return fmt.Errorf("dwarf stack underflow at %x",
					st.loc)
			}
			st.stackNdx--
			st.cur = st.stack[st.stackNdx]
		case cfaDefCfa:
			st.cur.cfa.reg = r.uleb()
			st.cur.cfa.off = sleb128(r.uleb())
		case cfaDefCfaRegister:
			st.cur.cfa.reg = r.uleb()
		case cfaDefCfaOffset:
			st.cur.cfa.off = sleb128(r.uleb())
		case cfaDefCfaExpression:
			expr, err := r.expression()
			if err == nil {
				err = st.cur.cfa.expression(expr)
			}
			if err != nil {
				log.Debugf("DWARF expression error (CFA): %v", err)
			}
		case cfaExpression:
			reg := r.uleb()
			expr, err := r.expression()
			if r := st.cur.reg(reg); err == nil && r != nil {
				err = r.expression(expr)
				if err != nil && reg == x86RegRBP {
					log.Debugf("DWARF expression error (RBP): %v", err)
				}
			}
		case cfaOffsetExtendedSf:
			st.rule(r.uleb(), regCFA, r.sleb())
		case cfaDefCfaSf:
			st.cur.cfa.reg = r.uleb()
			st.cur.cfa.off = r.sleb() * st.cie.dataAlign
		case cfaDefCfaOffsetSf:
			st.cur.cfa.off = r.sleb() * st.cie.dataAlign
		case cfaValOffset:
			st.rule(r.uleb(), regCFAVal, sleb128(r.uleb()))
		case cfaValOffsetSf:
			st.rule(r.uleb(), regCFAVal, r.sleb())
		case cfaValExpression:
			// Not really supported, just mark the register undefined
			st.rule(r.uleb(), regUndefined, 0)
			r.Discard(int(r.uleb()))
		case cfaGNUWindowSave:
			// No handling needed
		case cfaGNUArgsSize:
			// TODO: support this. It means there's callee removed
			// arguments in the stack. Fortunately, it seems that
			// RBP is often used as CFA base in these case, so this
			// likely is does not need further support.
			// At least glibc built libstdc++.so.6.0.25 had these.
			r.uleb()
		case cfaGNUNegOffsetExtended:
			st.rule(r.uleb(), regCFA, -r.sleb())
		case cfaAdvanceLoc:
			st.advance(int(operand))
			return nil
		case cfaOffset:
			st.rule(uleb128(operand), regCFA, sleb128(r.uleb()))
		case cfaRestore:
			st.restore(uleb128(operand))
		default:
			return fmt.Errorf("DWARF opcode %#02x not implemented",
				opcode)
		}
	}
	return nil
}

// parseLengthAndMarker parses the common part of CIE and FDE blocks.
// Returns amount of bytes left in the block, and CIE position (or -1 if this is a CIE).
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (r *reader) parseLengthAndMarker() (en, ciePos int64, err error) {
	var cieMarker, size int64
	length := int64(r.Uint32())
	if length == 0 {
		return 0, 0, errEmptyEntry
	}
	if length < 0xfffffff0 {
		// Normal 32-bit dwarf
		ciePos = int64(r.Uint32())
		cieMarker = 0xffffffff
		size = 4
	} else if length == 0xffffffff {
		// 64-bit dwarf
		length = r.Int64()
		ciePos = r.Int64()
		cieMarker = -1
		size = 8
	} else {
		return 0, 0, fmt.Errorf("unsupported initial length %#x", length)
	}

	if r.debugFrame {
		if ciePos == cieMarker {
			ciePos = -1
		}
	} else {
		// In .eh_frame's the CIE marker pointer value is zero,
		// and the FDE pointer is relative to its header position,
		// not to the start of section.
		if ciePos == 0 {
			ciePos = -1
		} else {
			ciePos = r.Tell() - size - ciePos
		}
	}

	if length < size || ciePos < -2 {
		return 0, 0, fmt.Errorf("unsupported header %#x/%#x", length, ciePos)
	}

	return int64(length) - size, ciePos, nil
}

// parseCIE reads and processes one Common Information Entry
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (r *reader) parseCIE(length int64) (*cieInfo, error) {
	if err := r.StartSection(length); err != nil {
		return nil, err
	}
	defer r.EndSection()

	ver := r.Uint8()
	if ver != 1 && ver != 3 && ver != 4 {
		return nil, fmt.Errorf("CIE version %d not supported", ver)
	}

	cie := &cieInfo{
		enc:     encFormatNative | encAdjustAbs,
		ldsaEnc: encFormatNative | encAdjustAbs,
	}

	augmentation, err := r.ReadString(0)
	if err != nil {
		return nil, err
	}
	if len(augmentation) > 8 {
		return nil, fmt.Errorf("augmentation string too long '%s'", augmentation)
	}
	augmentation = strings.Clone(augmentation)

	if ver == 4 {
		// CIE version 4 adds two new fields we don't make use of yet. But we need to
		// read them so the rest of the data is aligned correctly.

		// Skip the address_size and segment_selector_size fields
		r.Discard(2)
	}

	cie.codeAlign = r.uleb()
	cie.dataAlign = r.sleb()
	if ver == 1 {
		cie.regRA = uleb128(r.Uint8())
	} else {
		cie.regRA = r.uleb()
	}

	// A zero length string indicates that no augmentation data is present.
	if len(augmentation) > 0 {
		// Parse rest of CIE header based on augmentation string
		if augmentation[0] != 'z' {
			return nil, fmt.Errorf("too old augmentation string '%s'", augmentation)
		}
		r.uleb()
		cie.hasAugmentation = true

		for _, ch := range string(augmentation[1:]) {
			switch ch {
			case 'L':
				cie.ldsaEnc = encoding(r.Uint8())
			case 'R':
				cie.enc = encoding(r.Uint8())
			case 'P':
				// remove the indirect as it's not supported, but we
				// don't use the result here anyway
				enc := encoding(r.Uint8()) &^ encIndirect
				if _, err = r.ptr(enc); err != nil {
					return nil, err
				}
			case 'S':
				cie.isSignalHandler = true
			default:
				return nil, fmt.Errorf("unsupported augmentation string '%s'",
					augmentation)
			}
		}
	}

	// initialize vmRegs from initialState - these can be used by restore
	// opcode during initial CIE run
	cie.initialState = newVMRegs(r.machine)

	// Run CIE initial opcodes
	st := state{
		cie: cie,
		cur: newVMRegs(r.machine),
	}
	if err := st.step(r); err != nil {
		return nil, err
	}
	cie.initialState = st.cur

	return cie, nil
}

// getUnwindInfo generates the needed unwind information from the register set
func (regs *vmRegs) getUnwindInfo(allowGenericRegisters bool) sdtypes.UnwindInfo {
	var info sdtypes.UnwindInfo
	switch regs.arch {
	case elf.EM_AARCH64:
		info = regs.getUnwindInfoARM()
	case elf.EM_X86_64:
		info = regs.getUnwindInfoX86()
	default:
		panic(fmt.Sprintf("architecture %d is not supported", regs.arch))
	}
	if !allowGenericRegisters && info.Flags&support.UnwindFlagLeafOnly != 0 {
		return sdtypes.UnwindInfoInvalid
	}
	return info
}

// newVMRegs initializes vmRegs structure for given architecture
func newVMRegs(arch elf.Machine) vmRegs {
	switch arch {
	case elf.EM_AARCH64:
		return newVMRegsARM()
	case elf.EM_X86_64:
		return newVMRegsX86()
	default:
		panic(fmt.Sprintf("architecture %d is not supported", arch))
	}
}

// isSignalTrampoline matches a given FDE against well known signal return handler
// code sequence.
func isSignalTrampoline(efCode *pfelf.File, fde *fdeInfo) bool {
	sigretCode, ok := sigretCodeMap[efCode.Machine]
	if !ok {
		return false
	}
	if fde.ipLen != uintptr(len(sigretCode)) {
		return false
	}
	fdeCode, err := efCode.VirtualMemory(int64(fde.ipStart), len(sigretCode), 64)
	if err != nil {
		return false
	}
	return bytes.Equal(fdeCode, sigretCode)
}

func processCIE(r *reader, ciePos int64, cieCache *lru.LRU[int64, *cieInfo]) (*cieInfo, error) {
	// Calculate CIE location, and get and cache the CIE data
	if cie, ok := cieCache.Get(ciePos); ok {
		return cie, nil
	}

	rdr := pfbufio.NewReader(r.Outer())
	defer pfbufio.PutReader(rdr)

	cr := &reader{
		Reader:     rdr,
		machine:    r.machine,
		debugFrame: r.debugFrame,
		vaddr:      r.vaddr,
	}
	cr.Seek(ciePos, io.SeekStart)
	r.SetBufferSize(256) // CIE entry is typically 20-80 bytes

	length, marker, err := cr.parseLengthAndMarker()
	if err != nil {
		return nil, err
	}
	if marker >= 0 {
		return nil, errUnexpectedType
	}
	if cie, err := cr.parseCIE(length); err == nil {
		cieCache.Add(ciePos, cie)
		return cie, nil
	} else {
		return nil, err
	}
}

// parseFDE reads and processes one Frame Description Entry from the reader 'r'.
// It reads the FDE specific data, and amends the intervals to deltas table if needed.
// The FDE format is described in:
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (r *reader) parseFDE(id, n int64, ipStart uintptr, cie *cieInfo, ee *elfExtractor) (fdeInfo, error) {
	err := r.StartSection(n)
	if err != nil {
		return fdeInfo{}, err
	}
	defer r.EndSection()

	// Parse FDE header
	fde := fdeInfo{id: id}
	fde.ipStart, err = r.ptr(cie.enc)
	if err != nil {
		return fde, err
	}
	if ipStart != 0 && fde.ipStart != ipStart {
		return fde, fmt.Errorf(
			"FDE ipStart (%x) not matching search table FDE ipStart (%x)",
			fde.ipStart, ipStart)
	}
	if cie.enc&encIndirect != 0 {
		fde.ipLen, err = r.ptr(cie.enc)
	} else {
		fde.ipLen, err = r.ptr(cie.enc & (encFormatMask | encSignedMask))
	}
	if err != nil {
		return fde, err
	}
	if cie.hasAugmentation {
		r.Discard(int(r.uleb()))
	}

	// Exit early if no stack delta extraction is done
	if ee == nil {
		return fde, nil
	}

	st := state{cie: cie, cur: cie.initialState}

	// Process the FDE opcodes
	if !ee.hooks.fdeHook(st.cie, &fde) {
		return fde, nil
	}

	bb := sdtypes.BasicBlock{
		Start: uint64(fde.ipStart),
		End:   uint64(fde.ipStart + fde.ipLen),
	}

	if st.cie.isSignalHandler || isSignalTrampoline(ee.file, &fde) {
		info := sdtypes.UnwindInfoSignal
		ee.hooks.deltaHook(st.loc, &st.cur, info)
		bb.Deltas.Add(0, info)
	} else {
		for r.Remaining() > 0 {
			loc := st.loc
			if err := st.step(r); err != nil {
				return fde, err
			}
			info := st.cur.getUnwindInfo(ee.allowGenericRegs)
			ee.hooks.deltaHook(fde.ipStart+loc, &st.cur, info)
			bb.Deltas.Add(uint32(loc), info)
		}
	}
	ee.intervals.Add(bb)

	return fde, nil
}

// elfRegion contains an area of ELF file with its virtual address start.
type elfRegion struct {
	offset int64
	length int64
	vaddr  uint64
}

func (r *elfRegion) Valid() bool {
	return r.length > 0
}

// elfRegionFromSection checks whether a given ELF section looks valid and has data, then
// creating a elfRegion for it. Otherwise, returns `nil`.
func elfRegionFromSection(s *pfelf.Section) elfRegion {
	if s == nil || s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_COMPRESSED != 0 {
		return elfRegion{}
	}
	return elfRegion{
		offset: int64(s.Offset),
		length: int64(s.Size),
		vaddr:  s.Addr,
	}
}

type ehframeInfo struct {
	header      elfRegion
	frames      elfRegion
	hdr         ehFrameHdr
	tableOffset int64
}

// parseEhframe resolves the .eh_frame_hdr and .eh_frame and reads the header if available.
func readEhframe(ef *pfelf.File) (*ehframeInfo, error) {
	var info ehframeInfo

	// Use section headers first, they are most accurate and usually present.
	info.header = elfRegionFromSection(ef.Section(".eh_frame_hdr"))
	info.frames = elfRegionFromSection(ef.Section(".eh_frame"))

	if !info.header.Valid() {
		// If header was not available, try the PT_GNU_EH_FRAME tag
		if p := ef.ProgByType(elf.PT_GNU_EH_FRAME); p != nil {
			info.header = elfRegion{
				offset: int64(p.Off),
				length: int64(p.Filesz),
				vaddr:  p.Vaddr,
			}
		}
	}

	if info.header.Valid() {
		// Cap read-ahead to header with two pointers (don't read the search table)
		hdrLength := int64(unsafe.Sizeof(ehFrameHdr{}) + 2*8)
		rdr := pfbufio.NewReader(ef.Underlying(), info.header.offset, hdrLength)
		defer pfbufio.PutReader(rdr)
		r := reader{
			Reader:  rdr,
			machine: ef.Machine,
			vaddr:   info.header.vaddr,
		}

		// Read and parse the header
		if _, err := r.Read(pfunsafe.FromPointer(&info.hdr)); err != nil {
			return nil, err
		}
		if info.hdr.version != 1 {
			return nil, fmt.Errorf("eh_frame_hdr version %d not supported",
				info.hdr.version)
		}
		if info.hdr.tableEnc != encAdjustDataRel+encSignedMask+encFormatData4 {
			return nil, fmt.Errorf("eh_frame_hdr table encoding %#x not supported",
				info.hdr.tableEnc)
		}
		framePtr, err := r.ptr(info.hdr.ehFramePtrEnc)
		if err != nil {
			return nil, fmt.Errorf("eh_frame_hdr frame pointer: %v", err)
		}
		info.tableOffset = r.Tell()

		if !info.frames.Valid() {
			if p := ef.ProgByVirtualAddress(uint64(framePtr)); p != nil {
				fileoffset := p.Off + uint64(framePtr) - p.Vaddr
				info.frames = elfRegion{
					offset: int64(fileoffset),
					length: int64(p.Filesz + p.Off - fileoffset),
					vaddr:  uint64(framePtr),
				}
			}
		}
	}

	return &info, nil
}

// walkFDEs walks .debug_frame or .eh_frame section, and processes it for stack deltas.
func (ee *elfExtractor) walkFDEs(ef *pfelf.File, frames elfRegion, debugFrame bool) error {
	var err error

	cieCache, err := lru.New[int64, *cieInfo](cieCacheSize, hashInt64)
	if err != nil {
		return err
	}

	// Walk the section, and process each CIE and FDE it contains
	rdr := pfbufio.NewReader(ef.Underlying(), frames.offset, frames.length)
	defer pfbufio.PutReader(rdr)

	r := &reader{
		Reader:     rdr,
		machine:    ef.Machine,
		debugFrame: debugFrame,
		vaddr:      frames.vaddr,
	}

	for rdr.Remaining() > 0 {
		id := r.Tell()
		n, ciePos, err := r.parseLengthAndMarker()
		if err != nil {
			// Zero terminator is section end marker
			if err == errEmptyEntry {
				break
			}
			return fmt.Errorf("failed to parse CIE/FDE near %#x: %v", id, err)
		}
		if ciePos < 0 {
			if cie, err := r.parseCIE(n); err == nil {
				cieCache.Add(id, cie)
			} else {
				return fmt.Errorf("failed to parse CIE %#x: %v", id, err)
			}
		} else {
			cie, err := processCIE(r, ciePos, cieCache)
			if err != nil {
				return fmt.Errorf("failed to parse FDE %#x: CIE %#x: %v", id, ciePos, err)
			}

			if _, err = r.parseFDE(id, n, 0, cie, ee); err != nil {
				return fmt.Errorf("failed to parse FDE %#x: %v", id, err)
			}
		}
	}
	return nil
}

func hashInt64(u int64) uint32 {
	return uint32(hash.Uint64(uint64(u)))
}

// parseEHFrame parses the .eh_frame DWARF info, extracting stack deltas.
func (ee *elfExtractor) parseEHFrame() error {
	info, err := readEhframe(ee.file)
	if err != nil || !info.frames.Valid() {
		return err
	}
	return ee.walkFDEs(ee.file, info.frames, false)
}

// parseDebugFrame parses the .debug_frame DWARF info, extracting stack deltas.
func (ee *elfExtractor) parseDebugFrame(ef *pfelf.File) error {
	debugFrames := elfRegionFromSection(ef.Section(".debug_frame"))
	if !debugFrames.Valid() {
		return nil
	}
	return ee.walkFDEs(ef, debugFrames, true)
}
