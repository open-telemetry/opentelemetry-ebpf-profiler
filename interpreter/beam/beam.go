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

	"github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// regex for matching the process name
	beamRegex                      = regexp.MustCompile(`beam.smp`)
	_         interpreter.Data     = &beamData{}
	_         interpreter.Instance = &beamInstance{}
)

type beamData struct {
	version                uint32
	the_active_code_index  uint64
	r                      uint64
	beam_normal_exit       uint64
	erts_atom_table        uint64
	erts_frame_layout      uint64
	etp_ptr_mask           uint64
	etp_header_subtag_mask uint64
	etp_heap_bits_subtag   uint64

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
		// In OTP 28, we need to look it up as a binary:
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/atom.h#L50-L59
		atom struct {
			len, name uint8
			u         struct {
				bin uint8
			}
		}

		// ErlHeapBits
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_bits.h#L149-L154
		erl_heap_bits struct {
			data uint8
		}
	}
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid         libpf.PID
	data        *beamData
	rm          remotememory.RemoteMemory
	rangesPtr   libpf.Address
	atomTable   libpf.Address
	atomCache   map[uint32]string
	stringCache *freelru.LRU[libpf.Address, libpf.String]

	// prefixes is indexed by the prefix added to ebpf maps (to be cleaned up) to its generation
	prefixes map[lpm.Prefix]uint32
	// mappingGeneration is the current generation (so old entries can be pruned)
	mappingGeneration uint32
}

func readReleaseVersion(ef *pfelf.File) (uint32, string, error) {
	sym, otpRelease, err := ef.SymbolData("etp_otp_release", 4)
	if err != nil {
		return 0, "", fmt.Errorf("failed to read OTP release: %v", err)
	}

	// Slice off the null termination before converting
	otpMajor, err := strconv.Atoi(string(otpRelease[:sym.Size-1]))
	if err != nil {
		return 0, "", fmt.Errorf("failed to parse OTP version: %v", err)
	}

	sym, ertsVersion, err := ef.SymbolData("etp_erts_version", 64)
	if err != nil {
		return 0, "", fmt.Errorf("failed to read erts version: %v", err)
	}

	return uint32(otpMajor), string(ertsVersion[:sym.Size-1]), nil
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

	otpVersion, ertsVersion, err := readReleaseVersion(ef)
	if err != nil {
		return nil, err
	}

	// TODO: We want to avoid reading static symbols to find the address of r here,
	// because it would be removed if the binary is stripped, but it seems that's the only
	// way to get it currently. Look into programmatically calculating it by disassembly.
	// If possible, get it exported in erl_etp.c
	symbols, err := ef.ReadSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read symbols: %v", err)
	}

	// "r" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	r, err := symbols.LookupSymbolAddress(libpf.SymbolName("r"))
	if err != nil {
		return nil, fmt.Errorf("symbol 'r' not found: %v", err)
	}

	// "the_active_code_index" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
	codeIndex, _, err := ef.SymbolData("the_active_code_index", 4)
	if err != nil {
		return nil, fmt.Errorf("symbol 'the_active_code_index' not found: %v", err)
	}

	// "erts_atom_table" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/atom.c#L35
	atomTable, _, err := ef.SymbolData("erts_atom_table", 128)
	if err != nil {
		return nil, fmt.Errorf("symbol 'erts_atom_table' not found: %v", err)
	}

	// "etp_ptr_mask" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L82-L85
	_, etp_ptr_mask, err := ef.SymbolData("etp_ptr_mask", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_ptr_mask' not found: %v", err)
	}

	// "etp_header_subtag_mask" is from:
	// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L132
	_, etp_header_subtag_mask, err := ef.SymbolData("etp_header_subtag_mask", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_header_subtag_mask' not found: %v", err)
	}

	// "etp_heap_bits_subtag" is from:
	// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L108
	_, etp_heap_bits_subtag, err := ef.SymbolData("etp_heap_bits_subtag", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_heap_bits_subtag' not found: %v", err)
	}

	// "beam_normal_exit" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/jit/beam_jit_main.cpp#L54
	beam_normal_exit, _, err := ef.SymbolData("beam_normal_exit", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'beam_normal_exit' not found: %v", err)
	}

	d := &beamData{
		version:                otpVersion,
		the_active_code_index:  uint64(codeIndex.Address),
		r:                      uint64(r),
		beam_normal_exit:       uint64(beam_normal_exit.Address),
		erts_atom_table:        uint64(atomTable.Address),
		etp_ptr_mask:           nopanicslicereader.Uint64(etp_ptr_mask, 0),
		etp_header_subtag_mask: nopanicslicereader.Uint64(etp_header_subtag_mask, 0),
		etp_heap_bits_subtag:   nopanicslicereader.Uint64(etp_heap_bits_subtag, 0),
	}

	// If erts_frame_layout is not defined, it means that frame pointers are not supported,
	// so we use a special address value to signify that they're not enabled.
	erts_frame_layout_symbol, _, err := ef.SymbolData("erts_frame_layout", 8)
	if err == nil {
		d.erts_frame_layout = uint64(erts_frame_layout_symbol.Address)
	} else {
		d.erts_frame_layout = ^uint64(0)
	}

	vms := &d.vmStructs

	// These values are the same on OTP releases 27.2.4 and 28.0.2.
	// We'll see what varies by version.
	vms.ranges.size_of = 32
	vms.ranges.modules = 0
	vms.ranges.n = 8
	vms.ranges_entry.size_of = 16
	vms.ranges_entry.start = 0
	vms.ranges_entry.end = 8
	vms.beam_code_header.num_functions = 0
	vms.beam_code_header.line_table = 72
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
	vms.erl_heap_bits.data = 16

	switch otpVersion {
	case 27:
		vms.beam_code_header.size_of = 144
		vms.beam_code_header.functions = 136
		vms.atom.name = 32
	case 28:
		vms.beam_code_header.size_of = 160
		vms.beam_code_header.functions = 152
		vms.atom.u.bin = 32
	default:
		return d, fmt.Errorf("unsupported OTP version for BEAM interpreter: %d", otpVersion)
	}

	log.Infof("BEAM loaded, OTP version: %d, ERTS version: %s", otpVersion, ertsVersion)

	return d, nil
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Infof("BEAM attaching, bias: 0x%x", bias)

	data := support.BEAMProcInfo{
		Version:               d.version,
		R:                     uint64(bias) + d.r,
		The_active_code_index: uint64(bias) + d.the_active_code_index,
		Beam_normal_exit:      uint64(bias) + d.beam_normal_exit,
		Ranges_sizeof:         uint8(d.vmStructs.ranges.size_of),
		Ranges_modules:        uint8(d.vmStructs.ranges.modules),
		Ranges_n:              uint8(d.vmStructs.ranges.n),
	}

	log.Infof("BEAM beam_normal_exit: 0x%x", data.Beam_normal_exit)

	if d.erts_frame_layout == ^uint64(0) {
		// If frame pointers are not supported, they will not be used
		data.Erts_frame_layout = uint64(0)
	} else {
		data.Erts_frame_layout = rm.Uint64(bias + libpf.Address(d.erts_frame_layout))
	}

	if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}

	stringCache, err := freelru.New[libpf.Address, libpf.String](
		interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	return &beamInstance{
		pid:         pid,
		data:        d,
		rm:          rm,
		rangesPtr:   bias + libpf.Address(d.r),
		atomTable:   bias + libpf.Address(d.erts_atom_table),
		prefixes:    make(map[lpm.Prefix]uint32),
		atomCache:   make(map[uint32]string),
		stringCache: stringCache,
	}, nil
}

func (d *beamData) Unload(_ interpreter.EbpfHandler) {
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler, _ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	i.mappingGeneration++
	vms := i.data.vmStructs

	codeIndex := i.rm.Uint32(libpf.Address(i.data.the_active_code_index))
	activeRanges := i.rangesPtr + libpf.Address(uint32(vms.ranges.size_of)*codeIndex)
	modules := i.rm.Ptr(activeRanges + libpf.Address(vms.ranges.modules))

	n := i.rm.Uint64(activeRanges + libpf.Address(vms.ranges.n))

	for idx := uint64(0); idx < n; idx++ {
		moduleRange := modules + libpf.Address(idx*uint64(vms.ranges_entry.size_of))
		low := i.rm.Uint64(moduleRange + libpf.Address(vms.ranges_entry.start))
		high := i.rm.Uint64(moduleRange + libpf.Address(vms.ranges_entry.end))

		prefixes, err := lpm.CalculatePrefixList(low, high)
		if err != nil {
			return fmt.Errorf("new anonymous mapping lpm failure %#x - %#x", low, high)
		}

		for _, prefix := range prefixes {
			// log.Debugf("Enabling BEAM for %#v", prefix)

			_, exists := i.prefixes[prefix]
			if !exists {
				err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindBEAM, 0, 0)
				if err != nil {
					return err
				}
			}
			i.prefixes[prefix] = i.mappingGeneration
		}
	}

	// Remove prefixes not seen
	for prefix, generation := range i.prefixes {
		if generation == i.mappingGeneration {
			continue
		}
		log.Debugf("Disabling BEAM for %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(i.prefixes, prefix)
	}

	return nil
}

func (i *beamInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	log.Infof("BEAM interpreter detaching")
	return nil
}

func (i *beamInstance) Symbolize(frame *host.Frame, frames *libpf.Frames) error {
	if !frame.Type.IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}
	pc := libpf.Address(frame.Lineno)
	codeHeader := libpf.Address(frame.File)

	// log.Debugf("BEAM symbolizing pc: 0x%x", pc)

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

	log.Debugf("BEAM Found function %s at %s:%d", mfaName, fileName, lineNumber)
	frames.Append(&libpf.Frame{
		Type:         libpf.BEAMFrame,
		FunctionName: libpf.Intern(mfaName),
		SourceFile:   fileName,
		SourceLine:   libpf.SourceLineno(lineNumber),
	})

	return nil
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

func (i *beamInstance) findFileLocation(codeHeader libpf.Address, functionIndex uint64, pc libpf.Address) (fileName libpf.String, lineNumber uint64, err error) {
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

	return libpf.NullString, 0, fmt.Errorf("BEAM unable to find file and line number")
}

func (i *beamInstance) lookupAtom(index uint32) (string, error) {
	if value, ok := i.atomCache[index]; ok {
		return value, nil
	}

	vms := i.data.vmStructs

	segTable := i.rm.Ptr(i.atomTable + libpf.Address(vms.index_table.seg_table))
	segment := i.rm.Ptr(segTable + libpf.Address(8*(index>>16)))
	entry := i.rm.Ptr(segment + libpf.Address(8*((index>>6)&0x3FF)))

	len := i.rm.Uint16(entry + libpf.Address(vms.atom.len))

	name := make([]byte, len)
	switch i.data.version {
	case 27:
		err := i.rm.Read(i.rm.Ptr(entry+libpf.Address(vms.atom.name)), name)
		if err != nil {
			return "", fmt.Errorf("BEAM Unable to lookup atom with index %d: %v", index, err)
		}
	case 28:
		// Implementation based on https://github.com/erlang/otp/blob/OTP-28.0.2/erts/etc/unix/etp-commands.in#L657-L674
		unboxed := i.rm.Ptr(entry+libpf.Address(vms.atom.u.bin)) & libpf.Address(i.data.etp_ptr_mask)

		subtag := i.rm.Uint64(unboxed) & uint64(i.data.etp_header_subtag_mask)
		if subtag == uint64(i.data.etp_heap_bits_subtag) {
			err := i.rm.Read(unboxed+libpf.Address(vms.erl_heap_bits.data), name)
			if err != nil {
				return "", fmt.Errorf("BEAM Unable to lookup atom with index %d (ErlHeapBits tag): %v", index, err)
			}
		} else {
			return "", fmt.Errorf("BEAM Unable to lookup atom with index %d: expected boxed value subtag 0x%x, found 0x%x", index, i.data.etp_heap_bits_subtag, subtag)
		}
	}

	i.atomCache[index] = string(name)
	return string(name), nil
}

func (i *beamInstance) readErlangString(eterm libpf.Address, maxLength uint64) libpf.String {
	if value, ok := i.stringCache.Get(eterm); ok {
		return value
	}

	result := strings.Builder{}
	length := uint64(0)

	// TODO: Get this exported if possible in erl_etp.c
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/etc/unix/etp-commands.in#L5326
	etp_nil := libpf.Address(0x3B)

	for eterm != etp_nil && length < maxLength {
		charAddr := eterm & libpf.Address(i.data.etp_ptr_mask)
		charValue := i.rm.Uint64(charAddr)
		char := uint8(charValue >> 4)
		result.WriteByte(char)
		length++
		nextAddr := libpf.Address((eterm & libpf.Address(i.data.etp_ptr_mask)) + 8)
		eterm = libpf.Address(i.rm.Uint64(nextAddr))
	}

	if length > maxLength {
		result.WriteString("...")
	}

	value := libpf.Intern(result.String())
	i.stringCache.Add(eterm, value)

	return value
}
