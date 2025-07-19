// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// BEAM VM Unwinder support code

// The BEAM VM is an interpreter for Erlang, as well as several other languages
// that share the same bytecode, such as Elixir and Gleam.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// #include "../../support/ebpf/types.h"
// #include "../../support/ebpf/v8_tracer.h"
import "C"

var (
	// regex for matching the process name
	beamRegex                      = regexp.MustCompile(`beam.smp`)
	_         interpreter.Data     = &beamData{}
	_         interpreter.Instance = &beamInstance{}
)

type beamData struct {
	version               uint32
	the_active_code_index uint64
	r                     uint64
	erts_atom_table       uint64

	// Sizes and offsets BEAM internal structs we need to traverse
	vmStructs struct {
		// ranges
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
		ranges struct {
			size_of, modules, n uint8
		}

		// Range
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L31-L34
		ranges_entry struct {
			size_of, start, end uint8
		}

		// BeamCodeHeader
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L56-L125
		beam_code_header struct {
			size_of, num_functions, line_table, functions uint8
		}

		// ErtsCodeInfo
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L104-L123
		erts_code_info struct {
			size_of, mfa uint8
		}

		// ErtsCodeMFA
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L87-L95
		erts_code_mfa struct {
			size_of, module, function, arity uint8
		}

		// BeamCodeLineTab
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L130-L138
		beam_code_line_tab struct {
			size_of, fname_ptr, loc_size, loc_tab, func_tab uint8
		}

		// IndexTable
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/index.h#L39-L47
		index_table struct {
			seg_table uint8
		}

		// Atom
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/atom.h#L48-L54
		atom struct {
			len, name uint8
		}
	}
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid       libpf.PID
	data      *beamData
	rm        remotememory.RemoteMemory
	rangesPtr libpf.Address
	atomTable libpf.Address
}

func readSymbolValue(ef *pfelf.File, name libpf.SymbolName) ([]byte, error) {
	sym, err := ef.LookupSymbol(name)
	if err != nil {
		return nil, fmt.Errorf("symbol not found: %v", err)
	}

	memory := make([]byte, sym.Size)
	if _, err := ef.ReadVirtualMemory(memory, int64(sym.Address)); err != nil {
		return nil, fmt.Errorf("failed to read process memory at 0x%x:%v", sym.Address, err)
	}

	log.Infof("read symbol value %s: %s", sym.Name, memory)
	return memory, nil
}

func readReleaseVersion(ef *pfelf.File) (uint32, []byte, error) {
	otpRelease, err := readSymbolValue(ef, "etp_otp_release")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read OTP release: %v", err)
	}

	// Slice off the null termination before converting
	otpMajor, err := strconv.Atoi(string(otpRelease[:len(otpRelease)-1]))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse OTP version: %v", err)
	}

	ertsVersion, err := readSymbolValue(ef, "etp_erts_version")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read erts version: %v", err)
	}

	return uint32(otpMajor), ertsVersion, nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	matches := beamRegex.FindStringSubmatch(info.FileName())
	if matches == nil {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	symbols, err := ef.ReadSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read symbols: %v", err)
	}

	otpVersion, _, err := readReleaseVersion(ef)
	if err != nil {
		return nil, err
	}

	// "the_active_code_index" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
	the_active_code_index, err := ef.LookupSymbolAddress("the_active_code_index")
	if err != nil {
		return nil, fmt.Errorf("symbol 'the_active_code_index' not found: %v", err)
	}

	// "r" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	r, err := symbols.LookupSymbolAddress(libpf.SymbolName("r"))
	if err != nil {
		return nil, fmt.Errorf("symbol 'r' not found: %v", err)
	}

	// "erts_atom_table" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/atom.c#L35
	erts_atom_table, err := ef.LookupSymbolAddress("erts_atom_table")
	if err != nil {
		return nil, fmt.Errorf("symbol 'erts_atom_table' not found: %v", err)
	}

	interpRanges, err := info.GetSymbolAsRanges(libpf.SymbolName("process_main"))
	if err != nil {
		return nil, err
	}

	// TODO: Do we need this if all the actual code is JITed?
	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindBEAM, info.FileID(), interpRanges); err != nil {
		return nil, err
	}

	d := &beamData{
		version:               otpVersion,
		the_active_code_index: uint64(the_active_code_index),
		r:                     uint64(r),
		erts_atom_table:       uint64(erts_atom_table),
	}

	vms := &d.vmStructs

	// These values are based on OTP release 27.2.4.
	// We'll see what varies by version.
	vms.ranges.size_of = 32
	vms.ranges.modules = 0
	vms.ranges.n = 8
	vms.ranges_entry.size_of = 16
	vms.ranges_entry.start = 0
	vms.ranges_entry.end = 8
	vms.beam_code_header.size_of = 144
	vms.beam_code_header.num_functions = 0
	vms.beam_code_header.line_table = 72
	vms.beam_code_header.functions = 136
	vms.erts_code_info.size_of = 40
	vms.erts_code_info.mfa = 16
	vms.erts_code_mfa.module = 0
	vms.erts_code_mfa.function = 8
	vms.erts_code_mfa.arity = 16
	vms.beam_code_line_tab.size_of = 32
	vms.beam_code_line_tab.fname_ptr = 0
	vms.beam_code_line_tab.loc_size = 8
	vms.beam_code_line_tab.loc_tab = 16
	vms.beam_code_line_tab.func_tab = 24
	vms.index_table.seg_table = 120
	vms.atom.len = 24
	vms.atom.name = 32

	log.Infof("BEAM loaded, OTP version %d", otpVersion)

	return d, nil
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Infof("BEAM attaching, bias: 0x%x", bias)

	data := C.BEAMProcInfo{
		version:               C.u32(d.version),
		bias:                  C.u64(bias),
		r:                     C.u64(uint64(bias) + d.r),
		the_active_code_index: C.u64(uint64(bias) + d.the_active_code_index),
	}
	if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}

	return &beamInstance{
		pid:       pid,
		data:      d,
		rm:        rm,
		rangesPtr: bias + libpf.Address(d.r),
		atomTable: bias + libpf.Address(d.erts_atom_table),
	}, nil
}

func (d *beamData) Unload(_ interpreter.EbpfHandler) {
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler, _ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()

	// Index into the active static `r` variable using each valid index (the size of the `ranges` struct is 32 bytes)
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	// The max index is defined as 3 here: https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L70
	for codeIndex := 0; codeIndex < 3; codeIndex++ {
		activeRanges := i.rangesPtr + libpf.Address(32*codeIndex)

		// Use offsets into the `ranges` struct to get the beginning of the array and the number of entries based on
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
		modules := i.rm.Ptr(activeRanges)
		n := i.rm.Uint64(activeRanges + libpf.Address(8))

		low := i.rm.Ptr(modules)
		high := i.rm.Ptr(modules + libpf.Address((n-1)*16+8))

		log.Infof("Enabling BEAM for %#x - %#x", low, high)

		// TODO: I think this is resulting in the following error (figure out why):
		// ERRO[0004] Failed to handle new anonymous mapping for PID 375011: update: key already exists
		prefixes, err := lpm.CalculatePrefixList(uint64(low), uint64(high))
		if err != nil {
			return fmt.Errorf("new anonymous mapping lpm failure %#x - %#x: %v", low, high, err)
		}
		for _, prefix := range prefixes {
			err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindBEAM, 0, 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *beamInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	log.Infof("BEAM interpreter detaching")
	return nil
}

func (i *beamInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}
	pc := libpf.Address(frame.Lineno)
	activeRanges := libpf.Address(frame.File)

	log.Infof("BEAM symbolizing pc: 0x%x", pc)

	codeHeader, err := i.findCodeHeader(activeRanges, pc)
	if err != nil {
		return err
	}

	functionIndex, moduleID, functionID, arity, err := i.findMFA(pc, codeHeader)
	if err != nil {
		return err
	}

	moduleName, err := i.lookupAtom(moduleID)
	if err != nil {
		return err
	}
	functionName, err := i.lookupAtom(functionID)
	if err != nil {
		return err
	}

	mfaName := ""
	if strings.HasPrefix(moduleName, "Elixir.") {
		// This is an Elixir module, so format the function using Elixir syntax (without the "Elixir." prefix)
		mfaName = fmt.Sprintf("%s.%s/%d", moduleName[7:], functionName, arity)
	} else {
		// Assume it's Erlang and format it using Erlang syntax
		mfaName = fmt.Sprintf("%s:%s/%d", moduleName, functionName, arity)
	}

	fileName, lineNumber, err := i.findFileLocation(codeHeader, functionIndex, pc)
	if err != nil {
		return err
	}

	log.Warnf("BEAM Found function %s at %s:%d", mfaName, fileName, lineNumber)
	frameID := libpf.NewFrameID(libpf.NewFileID(0x0, uint64(codeHeader)), libpf.AddressOrLineno(pc))

	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: mfaName,
		SourceFile:   fileName,
		SourceLine:   libpf.SourceLineno(lineNumber),
	})
	trace.AppendFrameID(libpf.BEAMFrame, frameID)

	return nil
}

func (i *beamInstance) findCodeHeader(activeRanges libpf.Address, pc libpf.Address) (codeHeader libpf.Address, err error) {
	vms := i.data.vmStructs

	modules := i.rm.Ptr(activeRanges + libpf.Address(vms.ranges.modules))
	n := i.rm.Uint64(activeRanges + libpf.Address(vms.ranges.n))

	firstRange := modules
	lastRange := modules + libpf.Address((n-1)*uint64(vms.ranges_entry.size_of))

	low := i.rm.Ptr(firstRange + libpf.Address(vms.ranges_entry.start))
	high := i.rm.Ptr(lastRange + libpf.Address(vms.ranges_entry.end))

	if pc >= low && pc <= high {
		lowIdx := uint64(0)
		midIdx := uint64(0)
		highIdx := n - 1
		for lowIdx < highIdx {
			midIdx = lowIdx + (highIdx-lowIdx)/2
			midRange := modules + libpf.Address(midIdx*uint64(vms.ranges_entry.size_of))
			midStart := i.rm.Ptr(midRange + libpf.Address(vms.ranges_entry.start))
			midEnd := i.rm.Ptr(midRange + libpf.Address(vms.ranges_entry.end))
			if pc < midStart {
				highIdx = midIdx
			} else if pc >= midEnd {
				lowIdx = midIdx + 1
			} else {
				codeHeader = midStart
				break
			}
		}
	} else {
		return codeHeader, fmt.Errorf("PC 0x%x not in valid address ranges (0x%x - 0x%x)", pc, low, high)
	}

	return codeHeader, nil
}

func (i *beamInstance) findMFA(pc libpf.Address, codeHeader libpf.Address) (functionIndex uint64, moduleID uint32, functionID uint32, arity uint32, err error) {
	vms := i.data.vmStructs

	numFunctions := i.rm.Uint32(codeHeader + libpf.Address(vms.beam_code_header.num_functions))
	functions := codeHeader + libpf.Address(vms.beam_code_header.functions)

	ertsCodeInfo := libpf.Address(0)
	lowIdx := uint64(0)
	highIdx := uint64(numFunctions) - 1
	for lowIdx < highIdx {
		midIdx := lowIdx + (highIdx-lowIdx)/2
		midStart := i.rm.Ptr(functions + libpf.Address(midIdx*8))
		midEnd := i.rm.Ptr(functions + libpf.Address((midIdx+1)*8))
		if pc < midStart {
			highIdx = midIdx
		} else if pc >= midEnd {
			lowIdx = midIdx + 1
		} else {
			ertsCodeInfo = midStart
			functionIndex = midIdx

			mfa := ertsCodeInfo + libpf.Address(vms.erts_code_info.mfa)
			moduleID := i.rm.Uint32(mfa + libpf.Address(vms.erts_code_mfa.module))
			functionID := i.rm.Uint32(mfa + libpf.Address(vms.erts_code_mfa.function))
			arity := i.rm.Uint32(mfa + libpf.Address(vms.erts_code_mfa.arity))

			return functionIndex, moduleID, functionID, arity, nil
		}
	}

	return 0, 0, 0, 0, fmt.Errorf("BEAM unable to find the MFA for PC 0x%x in expected code range", pc)
}

func (i *beamInstance) findFileLocation(codeHeader libpf.Address, functionIndex uint64, pc libpf.Address) (fileName string, lineNumber uint64, err error) {
	vms := i.data.vmStructs

	lineTable := i.rm.Ptr(codeHeader + libpf.Address(vms.beam_code_header.line_table))
	functionTable := lineTable + libpf.Address(vms.beam_code_line_tab.func_tab)

	lineLow := i.rm.Ptr(functionTable + libpf.Address(8*functionIndex))
	lineHigh := i.rm.Ptr(functionTable + libpf.Address(8*(functionIndex+1)))

	// We need to align the lineMid values on 8-byte address boundaries
	bitmask := libpf.Address(^(uint64(0xf)))
	for lineHigh > lineLow {
		lineMid := lineLow + ((lineHigh-lineLow)/2)&bitmask

		if pc < i.rm.Ptr(lineMid) {
			lineHigh = lineMid
		} else if pc < i.rm.Ptr(lineMid+libpf.Address(8)) {
			firstLine := i.rm.Ptr(functionTable)
			locIndex := uint32((lineMid - firstLine) / 8)
			locSize := i.rm.Uint32(lineTable + libpf.Address(vms.beam_code_line_tab.loc_size))
			locTab := i.rm.Ptr(lineTable + libpf.Address(vms.beam_code_line_tab.loc_tab))
			locAddr := locTab + libpf.Address(locSize*locIndex)
			loc := uint64(0)
			if locSize == 2 {
				loc = uint64(i.rm.Uint16(locAddr))
			} else {
				loc = uint64(i.rm.Uint32(locAddr))
			}
			fnameIndex := loc >> 24
			fileNamePtr := libpf.Address(i.rm.Uint64(lineTable) + 8*fnameIndex)
			fileName = i.readErlangString(libpf.Address(i.rm.Uint64(fileNamePtr)), 256)

			return fileName, loc & ((1 << 24) - 1), nil
		} else {
			lineLow = lineMid + 8
		}
	}

	return "", 0, fmt.Errorf("BEAM unable to find file and line number")
}

func (i *beamInstance) lookupAtom(index uint32) (string, error) {
	vms := i.data.vmStructs

	segTable := i.rm.Ptr(i.atomTable + libpf.Address(vms.index_table.seg_table))
	segment := i.rm.Ptr(segTable + libpf.Address(8*(index>>16)))
	entry := i.rm.Ptr(segment + libpf.Address(8*((index>>6)&0x3FF)))

	len := i.rm.Uint16(entry + libpf.Address(vms.atom.len))

	name := make([]byte, len)
	err := i.rm.Read(i.rm.Ptr(entry+libpf.Address(vms.atom.name)), name)
	if err != nil {
		return "", fmt.Errorf("BEAM Unable to lookup atom with index %d: %v", index, err)
	}

	return string(name), nil
}

// TODO: read these values from the symbol table
const (
	ETP_NIL      = libpf.Address(0x3B)
	ETP_PTR_MASK = ^libpf.Address(0x3)
)

func (i *beamInstance) readErlangString(eterm libpf.Address, maxLength uint64) string {
	result := strings.Builder{}
	length := uint64(0)

	for eterm != ETP_NIL && length < maxLength {
		charAddr := eterm & ETP_PTR_MASK
		charValue := i.rm.Uint64(charAddr)
		char := uint8(charValue >> 4)
		result.WriteByte(char)
		length++
		nextAddr := libpf.Address((eterm & ETP_PTR_MASK) + 8)
		eterm = libpf.Address(i.rm.Uint64(nextAddr))
	}

	if length > maxLength {
		return result.String() + "..."
	}

	return result.String()
}
