// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfatbuf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Most files have single CIE, and all FDEs use that. But multiple CIEs are needed
// in some cases.
const cieCacheSize = 256

// errUnexpectedType is used internally to detect inconsistent FDE/CIE types
var errUnexpectedType = errors.New("unexpected FDE/CIE type")

// errEmptyEntry is used internally to report FDEs/CIEs of length 0.
var errEmptyEntry = errors.New("FDE/CIE empty")

// ehframeHooks interface provides hooks for filtering and debugging eh_frame parsing
type ehframeHooks interface {
	// fdeUnsorted is called if FDE entries from unsorted area are found.
	fdeUnsorted()
	// fdeHook is called for each FDE. Returns false if the FDE should be filtered out.
	fdeHook(cie *cieInfo, fde fdeInfo, deltas *sdtypes.StackDeltaArray) bool
	// deltaHook is called for each stack delta found
	deltaHook(ip uint64, regs *vmRegs, delta sdtypes.StackDelta)
	// golangHook is called if .gopclntab is found to report its coverage
	golangHook(start, end uint64)
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
	// fdeCount      ptr{ehFramePtrEnc}
	// searchTable   [fdeCount]struct {
	//	startIp ptr{tableEnc}
	//	fdeAddr ptr{tableEnc}
	// }
}

// reader provides read access to the Exception Frame section and the virtual address base.
type reader struct {
	debugFrame bool

	rd    *pfatbuf.Cache
	base  int64
	pos   int64
	end   int64
	vaddr uint64
}

// newReaderFromProg
func newReaderFromProg(prog *pfelf.Prog, cache *pfatbuf.Cache, name string, pos int64) reader {
	cache.InitName(name, prog)
	return reader{
		rd:    cache,
		vaddr: prog.Vaddr,
		pos:   pos,
		end:   int64(prog.Filesz),
	}
}

// newReaderFromSection
func newReaderFromSection(sec *pfelf.Section, debugFrame bool, cache *pfatbuf.Cache) reader {
	if sec == nil || sec.Type == elf.SHT_NOBITS {
		return reader{}
	}
	cache.InitName("eh.sec", sec)
	return reader{
		debugFrame: debugFrame,
		rd:         cache,
		vaddr:      sec.Addr,
		end:        int64(sec.FileSize),
	}
}

func (r *reader) setBase() {
	r.base = r.pos
}

// reader creates a "sub"-reader for the data starting from offset relative to base
func (r *reader) offset(offs int64) reader {
	return reader{
		debugFrame: r.debugFrame,
		rd:         r.rd,
		base:       r.base,
		pos:        r.base + offs,
		end:        r.end,
		vaddr:      r.vaddr,
	}
}

// hasData checks if the reader is still in valid state
func (r *reader) hasData() bool {
	return r.pos < r.end
}

// isValid checks if the reader is still in valid state
func (r *reader) isValid() bool {
	return r.rd != nil && r.pos <= r.end
}

func (r *reader) skip(num int64) {
	r.pos += num
}

func (r *reader) read(to []byte) error {
	_, err := r.rd.ReadAt(to, int64(r.pos))
	r.pos += int64(len(to))
	return err
}

// u8 reads one unsigned byte.
func (r *reader) u8() uint8 {
	v := r.rd.Uint8At(r.pos)
	r.pos++
	return v
}

// u16 reads one unsigned word.
func (r *reader) u16() uint16 {
	v := r.rd.Uint16At(r.pos)
	r.pos += 2
	return v
}

// u32 reads one unsigned word.
func (r *reader) u32() uint32 {
	v := r.rd.Uint32At(r.pos)
	r.pos += 4
	return v
}

// u64 reads one unsigned word.
func (r *reader) u64() uint64 {
	v := r.rd.Uint64At(r.pos)
	r.pos += 8
	return v
}

// uleb reads one unsigned little endian base-128 encoded value
func (r *reader) uleb() uleb128 {
	b := uint8(0x80)
	val := uleb128(0)
	for shift := 0; b&0x80 != 0; shift += 7 {
		b = r.u8()
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
		b = r.u8()
		val |= sleb128(b&0x7f) << shift
	}
	if b&0x40 != 0 {
		// Sign extend
		val |= sleb128(-1) << shift
	}
	return val
}

// str reads one zero-terminated string value. This is currently used
// to read augmentation string only which is a small (under 64 bytes string).
func (r *reader) str() string {
	str, err := r.rd.StringAt(r.pos)
	if err != nil {
		return ""
	}
	r.skip(int64(len(str) + 1))
	return str
}

// bytes reads one n-length byte array value
func (r *reader) bytes(num uint64) reader {
	pos := r.pos
	r.pos = pos + int64(num)
	if r.pos > r.end {
		return reader{}
	}
	return reader{
		debugFrame: r.debugFrame,
		rd:         r.rd,
		pos:        pos,
		end:        r.pos,
		vaddr:      r.vaddr,
	}
}

// expression reads one DWARF expression, and normalizes it in the sense that
// opcodes are returned in indexable slice and each opcode with operand is
// adjusted to it's basic value with operand separated. The concept is to allow
// pattern matching expression with opcodes sequences.
func (r *reader) expression() ([]dwarfExpression, error) {
	blen := uint64(r.uleb())
	ed := r.bytes(blen)
	expr := make([]dwarfExpression, 0, 8)
	for ed.hasData() {
		op := expressionOpcode(ed.u8())
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
				operand2: uleb128(ed.sleb()),
			})
		case op == opConstU, op == opPlusUConst:
			expr = append(expr, dwarfExpression{
				opcode:   op,
				operand1: ed.uleb(),
			})
		case op == opConstS:
			expr = append(expr, dwarfExpression{
				opcode:   op,
				operand1: uleb128(ed.sleb()),
			})
		case op == opDeref, op >= opRot && op <= opNE:
			expr = append(expr, dwarfExpression{opcode: op})
		default:
			return nil, fmt.Errorf("unsupported expression (length %v): op %#x", blen, op)
		}
	}
	return expr, nil
}

// ptr reads one pointer value encoded with enc encoding
func (r *reader) ptr(enc encoding) (uint64, error) {
	if enc == encOmit {
		return 0, nil
	}
	pos := uint64(r.pos)
	var val uint64
	switch enc & (encFormatMask | encSignedMask) {
	case encFormatData2:
		val = uint64(r.u16())
	case encFormatData4:
		val = uint64(r.u32())
	case encFormatData8, encFormatNative, encFormatData8 | encSignedMask:
		val = r.u64()
	case encFormatData2 | encSignedMask:
		val = uint64(int64(int16(r.u16())))
	case encFormatData4 | encSignedMask:
		val = uint64(int64(int32(r.u32())))
	default:
		return 0, fmt.Errorf("unsupported format encoding %#02x", enc)
	}

	switch enc & encAdjustMask {
	case encAdjustAbs:
	case encAdjustPcRel:
		val += pos + r.vaddr
	case encAdjustDataRel:
		val += r.vaddr
	default:
		return 0, fmt.Errorf("unsupported adjust encoding %#02x", enc)
	}

	if enc&encIndirect != 0 {
		return 0, fmt.Errorf("unsupported indirect encoding %#02x", enc)
	}

	return val, nil
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
	ciePos  uint64
	ipLen   uint64
	ipStart uint64
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
	loc uint64
	// cur is the current state of the virtual machine
	cur vmRegs
	// stash is the implicit stack of register states for remember/restore opcodes
	stack [2]vmRegs
	// stackNdx is the current stack nesting level for remember/restore opcodes
	stackNdx int
}

// advance increments current virtual address by given delta and code alignment
func (st *state) advance(delta int) {
	st.loc += uint64(delta * int(st.cie.codeAlign))
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

	for r.hasData() {
		opcode := cfaOpcode(r.u8())
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
			st.advance(int(r.u8()))
			return nil
		case cfaAdvanceLoc2:
			st.advance(int(r.u16()))
			return nil
		case cfaAdvanceLoc4:
			st.advance(int(r.u32()))
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
			r.pos += int64(r.uleb())
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

// parseHDR parses the common part of CIE and FDE blocks
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (r *reader) parseHDR(expectCIE bool) (data reader, ciePos uint64, err error) {
	var idPos, cieMarker uint64
	dlen := uint64(r.u32())
	if dlen == 0 {
		return reader{}, 0, errEmptyEntry
	}
	if dlen < 0xfffffff0 {
		// Normal 32-bit dwarf
		idPos = uint64(r.pos)
		ciePos = uint64(r.u32())
		cieMarker = 0xffffffff
		dlen -= 4
	} else if dlen == 0xffffffff {
		// 64-bit dwarf
		dlen = r.u64()
		idPos = uint64(r.pos)
		ciePos = r.u64()
		cieMarker = 0xffffffffffffffff
		dlen -= 2 * 8
	} else {
		// Abort reading as sync is lost
		r.pos = r.end
		return reader{}, 0, fmt.Errorf("unsupported initial length %#x", dlen)
	}

	data = r.bytes(dlen)
	if !data.isValid() {
		return reader{}, 0, fmt.Errorf("CIE/FDE %#x: extends beyond file end", ciePos)
	}
	if !r.debugFrame {
		// In .eh_frame's the CIE marker pointer value is zero
		cieMarker = 0
	}
	isCIE := ciePos == cieMarker
	if isCIE != expectCIE {
		return data, 0, errUnexpectedType
	}
	if !isCIE {
		if !r.debugFrame {
			// In .eh_frame, the FDE pointer is relative to its header position,
			// not to the start of section.
			ciePos = idPos - ciePos
		}
		if ciePos >= uint64(r.end) {
			return data, 0, fmt.Errorf("FDE starts beyond end at %#x", ciePos)
		}
	}
	return data, ciePos, nil
}

// parseCIE reads and processes one Common Information Entry
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (r *reader) parseCIE(cie *cieInfo) (data reader, err error) {
	data, _, err = r.parseHDR(true)
	if err != nil {
		return reader{}, err
	}

	ver := data.u8()
	if ver != 1 && ver != 3 && ver != 4 {
		return reader{}, fmt.Errorf("CIE version %d not supported", ver)
	}

	*cie = cieInfo{
		enc:     encFormatNative | encAdjustAbs,
		ldsaEnc: encFormatNative | encAdjustAbs,
	}

	augmentation := data.str()
	if ver == 4 {
		// CIE version 4 adds two new fields we don't make use of yet. But we need to
		// read them so the rest of the data is aligned correctly.

		// Skip the address_size field
		// Skip the segment_selector_size field
		data.skip(2)
	}

	cie.codeAlign = data.uleb()
	cie.dataAlign = data.sleb()
	if ver == 1 {
		cie.regRA = uleb128(data.u8())
	} else {
		cie.regRA = data.uleb()
	}

	// A zero length string indicates that no augmentation data is present.
	if len(augmentation) > 0 {
		// Parse rest of CIE header based on augmentation string
		if augmentation[0] != 'z' {
			return reader{}, fmt.Errorf("too old augmentation string '%s'", augmentation)
		}
		data.uleb()
		cie.hasAugmentation = true

		for _, ch := range string(augmentation[1:]) {
			switch ch {
			case 'L':
				cie.ldsaEnc = encoding(data.u8())
			case 'R':
				cie.enc = encoding(data.u8())
			case 'P':
				// remove the indirect as it's not supported, but we
				// don't use the result here anyway
				enc := encoding(data.u8()) &^ encIndirect
				if _, err = data.ptr(enc); err != nil {
					return reader{}, err
				}
			case 'S':
				cie.isSignalHandler = true
			default:
				return reader{}, fmt.Errorf("unsupported augmentation string '%s'",
					augmentation)
			}
		}
	}

	if !data.isValid() {
		return reader{}, errors.New("CIE not valid after header")
	}
	return data, err
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
	if fde.ipLen != uint64(len(sigretCode)) {
		return false
	}
	fdeCode := make([]byte, len(sigretCode))
	_, err := efCode.ReadAt(fdeCode, int64(fde.ipStart))
	if err != nil {
		return false
	}
	return bytes.Equal(fdeCode, sigretCode)
}

// parses first fields of FDE, specifically PC Begin, PC Range
func parsesFDEHeader(fdeReader *reader, efm elf.Machine, ipStart uint64,
	cieCache *lru.LRU[uint64, *cieInfo]) (r reader, fde fdeInfo, info *cieInfo, err error) {
	// Parse FDE header
	fdeID := fdeReader.pos
	fde = fdeInfo{}
	r, fde.ciePos, err = fdeReader.parseHDR(false)
	if err != nil {
		// parseHDR returns unconditionally the CIE/FDE entry length.
		// Also return the size here. This is to allow walkFDEs to use
		// this function and skip CIEs.
		return r, fde, nil, err
	}

	// Calculate CIE location, and get and cache the CIE data
	cie, ok := cieCache.Get(fde.ciePos)
	if !ok {
		cie = &cieInfo{}
		cr := fdeReader.offset(int64(fde.ciePos))
		cr, err = cr.parseCIE(cie)
		if err != nil {
			return r, fde, nil, fmt.Errorf("CIE %#x failed: %v", fde.ciePos, err)
		}

		// initialize vmRegs from initialState - these can be used by restore
		// opcode during initial CIE run
		cie.initialState = newVMRegs(efm)

		// Run CIE initial opcodes
		st := state{
			cie: cie,
			cur: newVMRegs(efm),
		}
		if err = st.step(&cr); err != nil {
			return r, fde, nil, err
		}
		if !cr.isValid() {
			return r, fde, nil, fmt.Errorf("CIE %x parsing failed", fde.ciePos)
		}
		cie.initialState = st.cur
		cieCache.Add(fde.ciePos, cie)
	}

	// Parse rest of FDE structure (CIE dependent part)

	fde.ipStart, err = r.ptr(cie.enc)
	if err != nil {
		return r, fde, nil, err
	}
	if ipStart != 0 && fde.ipStart != ipStart {
		return r, fde, nil, fmt.Errorf(
			"FDE ipStart (%x) not matching search table FDE ipStart (%x)",
			fde.ipStart, ipStart)
	}
	if cie.enc&encIndirect != 0 {
		fde.ipLen, err = r.ptr(cie.enc)
	} else {
		fde.ipLen, err = r.ptr(cie.enc & (encFormatMask | encSignedMask))
	}
	if err != nil {
		return r, fde, nil, err
	}

	if cie.hasAugmentation {
		r.skip(int64(r.uleb()))
	}
	if !r.isValid() {
		return r, fde, nil, fmt.Errorf("FDE %x not valid after header", fdeID)
	}
	return r, fde, cie, nil
}

// parseFDE reads and processes one Frame Description Entry from the reader 'r'.
// It reads the CIE/FDE entry, and amends the intervals to deltas table.
// The FDE format is described in:
// http://dwarfstd.org/doc/DWARF5.pdf §6.4.1
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
func (ee *elfExtractor) parseFDE(fdeReader *reader, ef *pfelf.File, ipStart uint64,
	cieCache *lru.LRU[uint64, *cieInfo], sorted bool) error {
	// Parse FDE header
	fdeID := fdeReader.pos
	r, fde, cie, err := parsesFDEHeader(fdeReader, ef.Machine, ipStart, cieCache)
	if err != nil {
		return err
	}
	st := state{cie: cie, cur: cie.initialState}

	// Process the FDE opcodes
	if !ee.hooks.fdeHook(st.cie, fde, ee.deltas) {
		return nil
	}
	st.loc = fde.ipStart
	if st.cie.isSignalHandler || isSignalTrampoline(ee.file, &fde) {
		delta := sdtypes.StackDelta{
			Address: uint64(st.loc),
			Hints:   sdtypes.UnwindHintKeep,
			Info:    sdtypes.UnwindInfoSignal,
		}
		ee.hooks.deltaHook(st.loc, &st.cur, delta)
		ee.deltas.AddEx(delta, sorted)
	} else {
		hint := sdtypes.UnwindHintKeep
		for r.hasData() {
			ip := st.loc
			if err := st.step(&r); err != nil {
				return err
			}
			delta := sdtypes.StackDelta{
				Address: uint64(ip),
				Hints:   hint,
				Info:    st.cur.getUnwindInfo(ee.allowGenericRegs),
			}
			ee.hooks.deltaHook(ip, &st.cur, delta)
			ee.deltas.AddEx(delta, sorted)
			sorted = true
			hint = sdtypes.UnwindHintNone
		}

		delta := sdtypes.StackDelta{
			Address: uint64(st.loc),
			Hints:   hint,
			Info:    st.cur.getUnwindInfo(ee.allowGenericRegs),
		}
		ee.deltas.AddEx(delta, sorted)

		if !r.isValid() {
			return fmt.Errorf("FDE %x parsing failed", fdeID)
		}
	}

	// Add end-of-function stop delta. This might later get removed if there is
	// another function starting on this address.
	ee.deltas.AddEx(sdtypes.StackDelta{
		Address: uint64(fde.ipStart + fde.ipLen),
		Hints:   sdtypes.UnwindHintEnd,
		Info:    sdtypes.UnwindInfoInvalid,
	}, sorted)

	return nil
}

type ehframeSections struct {
	header reader
	frames reader

	headerCache pfatbuf.Cache
	framesCache pfatbuf.Cache

	ehHdr    ehFrameHdr
	fdeCount uint64
}

// readEhHdr reads and validates the given `.eh_frame_hdr` section is in a format that we
// support. Returns if the header is valid.
func (es *ehframeSections) readEhHdr(r *reader) bool {
	if !r.isValid() {
		return false
	}
	if err := r.read(pfunsafe.FromPointer(&es.ehHdr)); err != nil {
		return false
	}
	if es.ehHdr.version != 1 {
		return false
	}
	// If the binary search table is in an unsupported format or omitted, we just ignore it
	// and go with the same approach as if the header wasn't present at all.
	if es.ehHdr.tableEnc != encAdjustDataRel+encSignedMask+encFormatData4 {
		return false
	}

	// Read the frame count
	if _, err := r.ptr(es.ehHdr.ehFramePtrEnc); err != nil {
		return false
	}
	fdeCount, err := r.ptr(es.ehHdr.fdeCountEnc)
	if err != nil {
		return false
	}
	es.fdeCount = fdeCount
	r.setBase()

	return true
}

// locatieSections attempts multiple different methods of locating
// the .eh_frame_hdr and .eh_frame ELF sections.
func (es *ehframeSections) locateSections(ef *pfelf.File) error {
	// Attempt to find .eh_frame{,_hdr} via their section header. This should work for the majority
	// of well-behaved ELF binaries.
	es.fdeCount = ^uint64(0)
	es.header = newReaderFromSection(ef.Section(".eh_frame_hdr"), false, &es.headerCache)
	es.frames = newReaderFromSection(ef.Section(".eh_frame"), false, &es.framesCache)

	// Validate whether we can use the eh_frame_hdr section.
	if ok := es.readEhHdr(&es.header); !ok {
		es.header = reader{}
	}

	// If we at least have the eh_frame section now, we can early-exit. The code below is a bit
	// more wobbly, so it's better to proceed without the header than to risk having to go with
	// the fallback.
	if es.frames.isValid() {
		return nil
	}

	// Attempt to locate the eh_frame section via the program headers. This is here to support
	// coredump binaries and other ELF files that have the section headers stripped.
	prog, hdrSz, err := ef.EHFrame()
	if err != nil {
		log.Debugf("No PT_GNU_EH_FRAME dynamic tag: %v", err)
		return nil
	}

	es.header = newReaderFromProg(prog, &es.headerCache, "eh.hdr", 0)
	es.frames = newReaderFromProg(prog, &es.framesCache, "eh.dat", int64(hdrSz))

	// Validate .eh_frame_hdr section.
	if ok := es.readEhHdr(&es.header); !ok {
		// There is no DWARF tag for the eh_frame section, just for the header. If the header
		// is not in a suitable format, we thus can't do a linear sweep of the FDEs, simply because
		// we have no idea where the actual list of FDEs starts. Thus, we pretend that the section
		// doesn't exist at all here.
		return errors.New("no suitable way to parsing eh_frame found")
	}

	// Some binaries only have the header, but no actual eh_frame section. This is, for example,
	// the case with cranelift generated binaries in coredumps, because they don't have the
	// eh_frame section in a PT_LOAD region.
	if !es.frames.hasData() {
		return errors.New("the eh_frame section is empty")
	}
	return nil
}

// walkFDEs walks .debug_frame or .eh_frame section, and processes it for stack deltas.
func (ee *elfExtractor) walkFDEs(ef *pfelf.File, frames *reader, numFDEs uint64) error {
	cieCache, err := lru.New[uint64, *cieInfo](cieCacheSize, hashUint64)
	if err != nil {
		return err
	}

	ee.hooks.fdeUnsorted()

	// Walk the section, and process each FDE it contains
	for frames.hasData() && numFDEs > 0 {
		pos := frames.pos
		err = ee.parseFDE(frames, ef, 0, cieCache, false)
		if err == nil {
			numFDEs--
		} else if err != errUnexpectedType && err != errEmptyEntry {
			return fmt.Errorf("failed to parse FDE %#x: %v", pos, err)
		}
	}

	return nil
}

func hashUint64(u uint64) uint32 {
	return uint32(hash.Uint64(u))
}

// parseEHFrame parses the .eh_frame DWARF info, extracting stack deltas.
func (ee *elfExtractor) parseEHFrame() error {
	var es ehframeSections

	err := es.locateSections(ee.file)
	if err != nil {
		return fmt.Errorf("failed to get EH sections: %w", err)
	}

	if !es.frames.isValid() {
		// No eh_frame section being present at all is not an error -- there's simply no data for
		// us to parse present.
		return nil
	}

	return ee.walkFDEs(ee.file, &es.frames, es.fdeCount)
}

// parseDebugFrame parses the .debug_frame DWARF info, extracting stack deltas.
func (ee *elfExtractor) parseDebugFrame(ef *pfelf.File) error {
	var cache pfatbuf.Cache

	frames := newReaderFromSection(ef.Section(".debug_frame"), true, &cache)
	if !frames.isValid() {
		return nil
	}
	return ee.walkFDEs(ef, &frames, ^uint64(0))
}
