// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	ah "github.com/open-telemetry/opentelemetry-ebpf-profiler/armhelpers"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/stringutil"

	aa "golang.org/x/arch/arm64/arm64asm"
)

// TSDInfo contains information to access C-library's Thread Specific Data from eBPF
type TSDInfo struct {
	// Offset is the pointer difference from "tpbase" pointer to the C-library
	// specific struct pthread's member containing the thread specific data:
	// .tsd (musl) or .specific (glibc).
	// Note: on x86_64 it's positive value, and arm64 it is negative value as
	// "tpbase" register has different purpose and pointer value per platform ABI.
	Offset int16

	// Multiplier is the TSD specific value array element size.
	// Typically 8 bytes on 64bit musl and 16 bytes on 64bit glibc
	Multiplier uint8

	// Indirect is a flag indicating if the "tpbase + Offset" points to a member
	// which is a pointer the array (musl) and not the array itself (glibc).
	Indirect uint8
}

// This code analyzes the C-library provided POSIX defined function which is used
// to read thread-specific data (TSD):
//   void *pthread_getspecific(pthread_key_t key);
//
// The actual symbol and its location is C-library specific:
//
// LIBC			DSO			Symbol
// musl/alpine		ld-musl-$ARCH.so.1	pthread_getspecific
// musl/generic		libc.musl-$ARCH.so.1	pthread_getspecific
// glibc/new		libc.so.6		__pthread_getspecific
// glibc/old		libpthread.so.0		__pthread_getspecific

// musl:
// http://git.musl-libc.org/cgit/musl/tree/src/internal/pthread_impl.h?h=v1.2.3#n49
// http://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_getspecific.c?h=v1.2.3#n4
//
// struct pthread {
//   ...
//   void **tsd;
//   ...
// };
//
// The implementation is just "return self->tsd[key];". We do the same.

// glibc:
// https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/descr.h;hb=c804cd1c00ad#l307
// https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/pthread_getspecific.c;hb=c804cd1c00ad#l23
//
// struct pthread {
//   ...
//   struct pthread_key_data {
//     uintptr_t seq;
//     void *data;
//   } specific_1stblock[PTHREAD_KEY_2NDLEVEL_SIZE];
//   struct pthread_key_data *specific[PTHREAD_KEY_1STLEVEL_SIZE];
//   ...
// }
//
// The 1st block is special cased for keys smaller than PTHREAD_KEY_2NDLEVEL_SIZE.
// We also assume we don't see large keys, and support only the small key case.
// Further both x86_64 and arm64 disassembler assume that small key code is the
// main code flow (as in, any conditional jumps are not followed).
//
// Reading the value is basically "return self->specific_1stblock[key].data;"

var (
	// regex for the libc
	libcRegex = regexp.MustCompile(`.*/(ld-musl|libc|libpthread)([-.].*)?\.so`)

	// error that a non-native architectures is not implemented (to skip tests)
	errArchNotImplemented = errors.New("architecture not implemented")
)

// IsPotentialTSDDSO determines if the DSO filename potentially contains pthread code
func IsPotentialTSDDSO(filename string) bool {
	return libcRegex.MatchString(filename)
}

// ExtractTSDInfo extracts the introspection data for pthread thread specific data.
func ExtractTSDInfo(ef *pfelf.File) (*TSDInfo, error) {
	sym, err := ef.LookupSymbol("__pthread_getspecific")
	if err != nil {
		sym, err = ef.LookupSymbol("pthread_getspecific")
		if err != nil {
			return nil, fmt.Errorf("no getspecific function: %s", err)
		}
	}
	if sym.Size < 8 {
		return nil, fmt.Errorf("getspecific function size is %d", sym.Size)
	}

	code := make([]byte, sym.Size)
	if _, err = ef.ReadVirtualMemory(code, int64(sym.Address)); err != nil {
		return nil, fmt.Errorf("failed to read getspecific function: %s", err)
	}

	info, err := ExtractTSDInfoNative(code)
	if err != nil {
		return nil, fmt.Errorf("failed to extract getspecific data: %s", err)
	}

	return &info, nil
}

const (
	Unspec int = iota
	TSDBase
	TSDElementBase
	TSDIndex
	TSDValue
	TSDConstant
)

type regState struct {
	status     int
	offset     int
	multiplier int
	indirect   bool
}

func ExtractTSDInfoARM64(code []byte) (TSDInfo, error) {
	// This tries to extract offsetof(struct pthread, tsd).
	// The analyzed code is pthread_getspecific, and should work on glibc and musl.
	// See test cases for example assembly. The strategy is to find "MRS xx, tpidr_el0"
	// instruction as loading something relative to "struct pthread". It is
	// then tracked against first argument to find the exact offset and multiplier
	// to address the TSD array.

	// Start tracking of X0
	var regs [32]regState

	regs[0].status = TSDIndex
	regs[0].multiplier = 1
	resetReg := int(-1)

	for offs := 0; offs < len(code); offs += 4 {
		if resetReg >= 0 {
			// Reset register state if something unsupported happens on it
			regs[resetReg] = regState{status: Unspec}
		}

		inst, err := aa.Decode(code[offs:])
		if err != nil {
			continue
		}
		if inst.Op == aa.RET {
			break
		}

		destReg, ok := ah.Xreg2num(inst.Args[0])
		if !ok {
			continue
		}

		resetReg = destReg
		switch inst.Op {
		case aa.MOV:
			var setImm bool
			switch val := inst.Args[1].(type) {
			case aa.Imm64:
				regs[destReg] = regState{
					status:     TSDConstant,
					offset:     int(val.Imm),
					multiplier: 1,
				}
				setImm = true
			case aa.Imm:
				regs[destReg] = regState{
					status:     TSDConstant,
					offset:     int(val.Imm),
					multiplier: 1,
				}
				setImm = true
			}
			if !setImm {
				// Track register moves
				srcReg, ok := ah.Xreg2num(inst.Args[1])
				if !ok {
					continue
				}
				regs[destReg] = regs[srcReg]
			}
		case aa.MRS:
			// MRS X1, S3_3_C13_C0_2
			if inst.Args[1].String() == "S3_3_C13_C0_2" {
				regs[destReg] = regState{
					status:     TSDBase,
					multiplier: 1,
				}
			}
		case aa.LDUR:
			// LDUR X1, [X1,#-88]
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				continue
			}
			srcReg, ok := ah.Xreg2num(m.Base)
			if !ok {
				continue
			}
			if regs[srcReg].status == TSDBase {
				imm, ok := ah.DecodeImmediate(m)
				if !ok {
					continue
				}
				regs[destReg] = regState{
					status:     TSDBase,
					offset:     regs[srcReg].offset + int(imm),
					multiplier: regs[srcReg].multiplier,
					indirect:   true,
				}
			} else {
				continue
			}
		case aa.LDR:
			switch m := inst.Args[1].(type) {
			case aa.MemExtend:
				// LDR X0, [X1,W0,UXTW #3]
				srcReg, ok := ah.Xreg2num(m.Base)
				if !ok {
					continue
				}
				srcIndex, ok := ah.Xreg2num(m.Index)
				if !ok {
					continue
				}
				if regs[srcReg].status == TSDBase && regs[srcIndex].status == TSDIndex {
					regs[destReg] = regState{
						status:     TSDValue,
						offset:     regs[srcReg].offset + (regs[srcIndex].offset << m.Amount),
						multiplier: regs[srcReg].multiplier << m.Amount,
						indirect:   regs[srcReg].indirect,
					}
				} else {
					continue
				}
			case aa.MemImmediate:
				// ldr x0, [x2, #8]
				srcReg, ok := ah.Xreg2num(m.Base)
				if !ok {
					continue
				}
				if regs[srcReg].status == TSDElementBase {
					i, ok := ah.DecodeImmediate(m)
					if !ok {
						continue
					}
					regs[destReg] = regState{
						status:     TSDValue,
						offset:     regs[srcReg].offset + int(i),
						multiplier: regs[srcReg].multiplier,
						indirect:   regs[srcReg].indirect,
					}
				} else {
					continue
				}
			}
		case aa.UBFIZ:
			// UBFIZ X0, X1, #4, #32
			srcReg, ok := ah.Xreg2num(inst.Args[1])
			if !ok {
				continue
			}
			if regs[srcReg].status == TSDIndex {
				i, ok := inst.Args[2].(aa.Imm)
				if !ok {
					continue
				}
				regs[destReg] = regState{
					status:     TSDIndex,
					offset:     regs[srcReg].offset << i.Imm,
					multiplier: regs[srcReg].multiplier << i.Imm,
				}
			}
		case aa.ADD:
			srcReg, ok := ah.Xreg2num(inst.Args[1])
			if !ok {
				continue
			}
			switch a2 := inst.Args[2].(type) {
			case aa.ImmShift:
				i, ok := ah.DecodeImmediate(a2)
				if !ok {
					continue
				}
				regs[destReg] = regs[srcReg]
				regs[destReg].offset += int(i)
			case aa.RegExtshiftAmount:
				regStr := inst.Args[2].String()
				shift := int(0)
				var fields [2]string
				if stringutil.SplitN(regStr, ",", fields[:]) == 2 {
					regStr = fields[0]
					n, err := fmt.Sscanf(fields[1], " LSL #%v", &shift)
					if n != 1 || err != nil {
						n, err := fmt.Sscanf(fields[1], " UXTW #%v", &shift)
						if n != 1 || err != nil {
							continue
						}
					}
				}
				reg, ok := ah.DecodeRegister(regStr)
				if !ok {
					continue
				}
				srcReg2, ok := ah.Xreg2num(aa.Reg(reg))
				if !ok {
					continue
				}
				if regs[srcReg].status == TSDBase && regs[srcReg2].status == TSDIndex {
					regs[destReg] = regState{
						status:     TSDElementBase,
						offset:     regs[srcReg].offset + regs[srcReg2].offset<<shift,
						multiplier: regs[srcReg2].multiplier << shift,
						indirect:   regs[srcReg].indirect,
					}
				} else if regs[srcReg].status == TSDConstant && regs[srcReg2].status == TSDIndex {
					regs[destReg] = regState {
						status: TSDIndex,
						offset: regs[srcReg].offset + regs[srcReg2].offset << shift,
						multiplier: regs[srcReg2].multiplier << shift,
					}
				} else {
					continue
				}
			}
		case aa.SUB:
			srcReg, ok := ah.Xreg2num(inst.Args[1])
			if !ok {
				continue
			}
			if regs[srcReg].status != Unspec {
				i, ok := ah.DecodeImmediate(inst.Args[2])
				if !ok {
					continue
				}
				regs[destReg] = regs[srcReg]
				regs[destReg].offset -= int(i)
			} else {
				continue
			}
		case aa.CMP, aa.CBZ:
			// Opcode with no affect on first argument.
			// Noop to exit switch without default continue.
		default:
			continue
		}
		resetReg = -1
	}

	if regs[0].status != TSDValue {
		return TSDInfo{}, errors.New("libc data not found")
	}

	indirect := uint8(0)
	if regs[0].indirect {
		indirect = 1
	}
	return TSDInfo{
		Offset:     int16(regs[0].offset),
		Multiplier: uint8(regs[0].multiplier),
		Indirect:   indirect,
	}, nil
}
