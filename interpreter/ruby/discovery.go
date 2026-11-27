// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tls"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Stripped Ruby 3.3+ can hide all the symbols needed by the unwinder. These
// deliberately bounded recognizers recover a subset of compiler patterns from
// exported functions, dynamic TLS relocations and the existing unwind intervals.
// They do not look for separate debug files. Unsupported builds keep the normal
// loader's failure/fallback behavior; no address is selected from ambiguous matches.
type rubyFunction struct {
	address uint64
	code    []byte
}

const maxRubyFunctionSize = 4096

func readRubyFunctions(ef *pfelf.File, names ...libpf.SymbolName) ([]rubyFunction, error) {
	fns := make([]rubyFunction, 0, len(names))
	for _, name := range names {
		sym, err := ef.LookupSymbol(name)
		if err != nil {
			return nil, err
		}
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Size == 0 || sym.Size > maxRubyFunctionSize {
			return nil, fmt.Errorf("unbounded Ruby function %s", name)
		}
		code, err := ef.VirtualMemory(int64(sym.Address), int(sym.Size), maxRubyFunctionSize)
		if err != nil {
			return nil, err
		}
		fns = append(fns, rubyFunction{uint64(sym.Address), code})
	}
	return fns, nil
}

// Different descriptor slots can refer to the same EC. Compare the resolved
// module offsets, not the slots or the eventual process-specific descriptors.
func consistentRubyEC(fns []rubyFunction, resolve func(rubyFunction) (*libpf.Symbol, error),
) (*libpf.Symbol, error) {
	var ec *libpf.Symbol
	for _, fn := range fns {
		sym, err := resolve(fn)
		if err != nil {
			return nil, err
		}
		if ec != nil && sym.Address != ec.Address {
			return nil, fmt.Errorf("inconsistent Ruby TLS accesses")
		}
		ec = sym
	}
	return ec, nil
}

func decodeRubyAMD(code []byte) (x86asm.Inst, error) {
	if ok, size := amd.DecodeSkippable(code); ok {
		return x86asm.Inst{Op: x86asm.NOP, Len: size}, nil
	}
	return x86asm.Decode(code, 64)
}

// rubyBranchTargets excludes intra-function control flow; its caller filters PLT stubs. The VM
// entry is the common tail-call target of rb_iseq_eval and rb_iseq_eval_main.
// On ARM64 the EC accessor is a common direct call from exported EC consumers.
func rubyBranchTargets(machine elf.Machine, fn rubyFunction, calls bool) (map[uint64]bool, error) {
	targets := make(map[uint64]bool)
	for off := 0; off < len(fn.code); {
		pc := fn.address + uint64(off)
		var target uint64
		switch machine {
		case elf.EM_AARCH64:
			ins, err := arm64asm.Decode(fn.code[off:])
			if err != nil {
				return nil, err
			}
			off += 4
			if (calls && ins.Op == arm64asm.BL) || (!calls && ins.Op == arm64asm.B) {
				if rel, ok := ins.Args[0].(arm64asm.PCRel); ok {
					target = uint64(int64(pc) + int64(rel))
				}
			}
		case elf.EM_X86_64:
			ins, err := decodeRubyAMD(fn.code[off:])
			if err != nil {
				return nil, fmt.Errorf("invalid Ruby instruction at %#x: %v", pc, err)
			}
			off += ins.Len
			if (calls && ins.Op == x86asm.CALL) || (!calls && ins.Op == x86asm.JMP) {
				if rel, ok := ins.Args[0].(x86asm.Rel); ok {
					target = uint64(int64(fn.address) + int64(off) + int64(rel))
				}
			}
		default:
			return nil, fmt.Errorf("unsupported Ruby machine %v", machine)
		}
		if target != 0 && (target < fn.address || target >= fn.address+uint64(len(fn.code))) {
			targets[target] = true
		}
	}
	return targets, nil
}

func commonRubyTarget(ef *pfelf.File, calls bool, fns []rubyFunction) (uint64, error) {
	text := ef.Section(".text")
	if text == nil {
		return 0, fmt.Errorf("missing Ruby .text section")
	}
	var common map[uint64]bool
	for _, fn := range fns {
		targets, err := rubyBranchTargets(ef.Machine, fn, calls)
		if err != nil {
			return 0, err
		}
		if common == nil {
			common = targets
		} else {
			for target := range common {
				if !targets[target] {
					delete(common, target)
				}
			}
		}
		if len(common) == 0 {
			break
		}
	}
	for target := range common {
		if target < text.Addr || target-text.Addr >= text.Size {
			delete(common, target)
		}
	}
	if len(common) == 1 {
		for target := range common {
			return target, nil
		}
	}
	return 0, fmt.Errorf("expected one common Ruby target, found %d", len(common))
}

// The ARM64 Ruby 4.0.1 fixture has a 404-byte rb_vm_exec. The minimum size is
// a heuristic to reject small shared helpers, not a guaranteed VM size bound.
const (
	minRubyVMSize = 256
	maxRubyVMSize = 65536
)

func discoverRubyVM(ef *pfelf.File, info *interpreter.LoaderInfo) ([]util.Range, error) {
	fns, err := readRubyFunctions(ef, "rb_iseq_eval", "rb_iseq_eval_main")
	if err != nil {
		return nil, err
	}
	entry, err := commonRubyTarget(ef, false, fns)
	if err != nil {
		return nil, err
	}
	block := info.Intervals().Find(entry)
	if block == nil || block.Start != entry {
		return nil, fmt.Errorf("no unwind interval starting at Ruby VM entry %#x", entry)
	}
	if size := block.End - entry; size < minRubyVMSize || size > maxRubyVMSize {
		return nil, fmt.Errorf("implausible size %d for Ruby VM entry %#x", size, entry)
	}
	return []util.Range{{Start: entry, End: block.End}}, nil
}

type rubyTLSAccess struct {
	slot             uint64
	loadOffset       int64
	resolverCall     uint64
	resolverIndirect bool
}

// rubyAMDTLSAccess recognizes LEA tls_index, CALL resolver, optional POP RBP,
// MOV [RAX+offset]. Track instruction ends separately: prefixes and epilogues
// must not change the base used for either RIP-relative operand.
func rubyAMDTLSAccess(fn rubyFunction) (rubyTLSAccess, error) {
	var candidate rubyTLSAccess
	var matches []rubyTLSAccess
	state, start := 0, 0
	for off := 0; off < len(fn.code); {
		ins, err := decodeRubyAMD(fn.code[off:])
		if err != nil {
			return rubyTLSAccess{}, fmt.Errorf("invalid AMD64 Ruby instruction at %#x", fn.address+uint64(off))
		}
		off += ins.Len
		end := fn.address + uint64(off)
		switch {
		case state == 1 && ins.Op == x86asm.CALL:
			switch target := ins.Args[0].(type) {
			case x86asm.Rel:
				candidate.resolverCall = uint64(int64(end) + int64(target))
			case x86asm.Mem:
				if target.Base != x86asm.RIP || target.Index != 0 || target.Segment != 0 {
					state = 0
					continue
				}
				candidate.resolverCall = uint64(int64(end) + target.Disp)
				candidate.resolverIndirect = true
			default:
				state = 0
				continue
			}
			state = 2
			continue
		case state == 2 && ins.Op == x86asm.POP && ins.Args[0] == x86asm.RBP:
			state = 3
			continue
		case (state == 2 || state == 3) && ins.Op == x86asm.MOV:
			load, loadOK := ins.Args[1].(x86asm.Mem)
			dst, dstOK := ins.Args[0].(x86asm.Reg)
			if dstOK && dst >= x86asm.RAX && dst <= x86asm.R15 && loadOK &&
				ins.AddrSize == 64 && load.Segment == 0 {
				// Restrict the shared scanner to this straight-line candidate:
				// it must follow this call result, not a later TLS access.
				candidate.slot, candidate.loadOffset, err = amd.ExtractTLSSlot(
					fn.code[start:off], fn.address+uint64(start))
				if err == nil {
					matches = append(matches, candidate)
				}
			}
		}
		state = 0
		if ins.Op == x86asm.LEA && ins.Args[0] == x86asm.RDI {
			if arg, ok := ins.Args[1].(x86asm.Mem); ok && arg.Base == x86asm.RIP && arg.Index == 0 && arg.Segment == 0 {
				candidate = rubyTLSAccess{}
				start, state = off-ins.Len, 1
			}
		}
	}
	if len(matches) != 1 {
		return rubyTLSAccess{}, fmt.Errorf("expected one Ruby TLS access, found %d", len(matches))
	}
	return matches[0], nil
}

// rubyAMDResolver verifies the resolver by its dynamic relocation, including
// calls through a PLT stub. The file's GOT pointer has not been relocated yet.
func rubyAMDResolver(ef *pfelf.File, access rubyTLSAccess) error {
	slot := access.resolverCall
	if !access.resolverIndirect {
		code, err := ef.VirtualMemory(int64(slot), 16, 16)
		if err != nil {
			return err
		}
		jump := false
		for len(code) > 0 {
			ins, err := decodeRubyAMD(code)
			if err != nil {
				return err
			}
			slot += uint64(ins.Len)
			code = code[ins.Len:]
			if ins.Op == x86asm.NOP {
				continue
			}
			mem, ok := ins.Args[0].(x86asm.Mem)
			if ins.Op != x86asm.JMP || !ok || mem.Base != x86asm.RIP || mem.Index != 0 || mem.Segment != 0 {
				return fmt.Errorf("unsupported Ruby TLS resolver stub")
			}
			slot = uint64(int64(slot) + mem.Disp)
			jump = true
			break
		}
		if !jump {
			return fmt.Errorf("missing Ruby TLS resolver jump")
		}
	}
	found := false
	err := ef.VisitRelocations(func(r pfelf.ElfReloc, name string, _ pfelf.RelocType) bool {
		found = r.Off == slot && name == "__tls_get_addr" && r.Addend == 0
		return !found
	}, pfelf.RelGlobDat|pfelf.RelJumpSlot)
	if err != nil || !found {
		return fmt.Errorf("no __tls_get_addr relocation at %#x: %v", slot, err)
	}
	return nil
}

func rubyAMDEC(ef *pfelf.File) (*libpf.Symbol, error) {
	fns, err := readRubyFunctions(ef, "rb_thread_current", "rb_fiber_current")
	if err != nil {
		return nil, err
	}
	// Each call is independently verified as __tls_get_addr.
	return consistentRubyEC(fns, func(fn rubyFunction) (*libpf.Symbol, error) {
		return rubyAMDFunctionEC(ef, fn)
	})
}

func rubyAMDFunctionEC(ef *pfelf.File, fn rubyFunction) (*libpf.Symbol, error) {
	access, err := rubyAMDTLSAccess(fn)
	if err != nil {
		return nil, err
	}
	if err := rubyAMDResolver(ef, access); err != nil {
		return nil, err
	}
	if access.loadOffset < 0 {
		return nil, fmt.Errorf("negative Ruby EC load offset %d", access.loadOffset)
	}
	return tls.AnonymousSlotSymbol(ef, libpf.Address(access.slot), access.loadOffset, pfelf.RelDTPMOD64)
}

func discoverRubyEC(ef *pfelf.File) (*libpf.Symbol, error) {
	var sym *libpf.Symbol
	var err error
	switch ef.Machine {
	case elf.EM_AARCH64:
		sym, err = rubyARMEC(ef)
	case elf.EM_X86_64:
		sym, err = rubyAMDEC(ef)
	default:
		return nil, fmt.Errorf("unsupported Ruby TLS machine %v", ef.Machine)
	}
	if err != nil {
		return nil, err
	}
	offset := uint64(sym.Address)
	prog := ef.ProgByType(elf.PT_TLS)
	if prog == nil || prog.Memsz < 8 || offset > prog.Memsz-8 || offset%8 != 0 {
		return nil, fmt.Errorf("recovered Ruby EC offset %#x is outside PT_TLS", offset)
	}
	return sym, nil
}

// rb_sym_immortal_count returns the first 32-bit field of ruby_global_symbols.
// Ruby 4 uses an acquire load and subtracts one from the counter.
func rubySymbolTable(machine elf.Machine, fn rubyFunction) (uint64, error) {
	switch machine {
	case elf.EM_AARCH64:
		return rubyARMSymbolTable(fn)
	case elf.EM_X86_64:
		return rubyAMDSymbolTable(fn)
	default:
		return 0, fmt.Errorf("unsupported Ruby symbol-table machine %v", machine)
	}
}

func rubyAMDSymbolTable(fn rubyFunction) (uint64, error) {
	if ok, size := amd.DecodeSkippable(fn.code); ok {
		fn = rubyFunction{fn.address + uint64(size), fn.code[size:]}
	}
	ins, err := x86asm.Decode(fn.code, 64)
	if err != nil || ins.Op != x86asm.MOV || ins.Args[0] != x86asm.EAX {
		return 0, fmt.Errorf("unproven AMD64 Ruby symbol-table load")
	}
	mem, ok := ins.Args[1].(x86asm.Mem)
	if !ok || mem.Base != x86asm.RIP || mem.Index != 0 || mem.Segment != 0 {
		return 0, fmt.Errorf("unproven AMD64 Ruby symbol-table load")
	}
	address := uint64(int64(fn.address) + int64(ins.Len) + mem.Disp)
	code := fn.code[ins.Len:]
	if len(code) == 4 && code[0] == 0x83 && code[1] == 0xe8 && code[2] == 1 {
		code = code[3:]
	}
	if len(code) != 1 || code[0] != 0xc3 {
		return 0, fmt.Errorf("unsupported AMD64 Ruby symbol-table return")
	}
	return address, nil
}

func discoverRubySymbols(ef *pfelf.File) (libpf.SymbolValue, error) {
	fns, err := readRubyFunctions(ef, "rb_sym_immortal_count")
	if err != nil {
		return 0, err
	}
	address, err := rubySymbolTable(ef.Machine, fns[0])
	if err != nil {
		return 0, err
	}
	prog := ef.ProgByVirtualAddress(address)
	if prog == nil || prog.Flags&elf.PF_W == 0 || prog.Vaddr+prog.Memsz-address < 24 || address%8 != 0 {
		return 0, fmt.Errorf("recovered Ruby symbol table %#x is outside writable memory", address)
	}
	return libpf.SymbolValue(address), nil
}
