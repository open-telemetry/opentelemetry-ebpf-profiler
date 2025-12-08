// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// BEAM VM Unwinder support code

// The BEAM VM is an interpreter for Erlang, as well as several other languages
// that share the same bytecode, such as Elixir and Gleam.

import (
	"fmt"
	"regexp"
	"strings"
	"unsafe"

	"github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// regex for matching the process name
	beamRegex                      = regexp.MustCompile(`(^|\/)beam\.smp`)
	_         interpreter.Data     = &beamData{}
	_         interpreter.Instance = &beamInstance{}
)

type beamData struct {
	otpRelease          string
	ertsVersion         string
	theActiveCodeIndex  libpf.Address
	r                   libpf.Address
	beamNormalExit      libpf.Address
	ertsFrameLayout     uint64
	ertsAtomTable       uint64
	etpPtrMask          uint64
	etpHeaderSubtagMask uint64
	etpHeapBitsSubtag   uint64
	// Sizes and offsets BEAM internal structs we need to traverse
	vmStructs struct {
		// ranges
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
		ranges struct {
			sizeOf uint8
		}

		// BeamCodeHeader
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L56-L125
		beamCodeHeader struct {
			sizeOf, numFunctions, lineTable, functions uint8
		}

		// ErtsCodeInfo
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L104-L123
		ertsCodeInfo struct {
			sizeOf, mfa uint8
		}

		// ErtsCodeMFA
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L87-L95
		ertsCodeMfa struct {
			sizeOf, module, function, arity uint8
		}

		// BeamCodeLineTab
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L130-L138
		beamCodeLineTab struct {
			sizeOf, fnamePtr, locSize, locTab, funcTab uint8
		}

		// IndexTable
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/index.h#L39-L47
		indexTable struct {
			segTable uint8
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
		erlHeapBits struct {
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

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	matches := beamRegex.FindStringSubmatch(info.FileName())
	if matches == nil {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	_, otpRelease, err := ef.SymbolData("etp_otp_release", 4)
	if err != nil {
		return nil, fmt.Errorf("failed to read OTP release: %v", err)
	}

	_, ertsVersion, err := ef.SymbolData("etp_erts_version", 64)
	if err != nil {
		return nil, fmt.Errorf("failed to read ERTS version: %v", err)
	}

	// "r" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	// TODO: We want to avoid reading static symbols to find the address of r here,
	// because it would be removed if the binary is stripped, but it seems that's the only
	// way to get it currently. If possible, we should get it exported in erl_etp.c
	var r libpf.Symbol
	ef.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "r" {
			r = sym
			return false
		} else {
			return true
		}
	})
	if r.Name != "r" {
		return nil, fmt.Errorf("symbol 'r' not found")
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
	_, etpPtrMask, err := ef.SymbolData("etp_ptr_mask", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_ptr_mask' not found: %v", err)
	}

	// "etp_header_subtag_mask" is from:
	// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L132
	_, etpHeaderSubtagMask, err := ef.SymbolData("etp_header_subtag_mask", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_header_subtag_mask' not found: %v", err)
	}

	// "etp_heap_bits_subtag" is from:
	// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L108
	_, etpHeapBitsSubtag, err := ef.SymbolData("etp_heap_bits_subtag", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_heap_bits_subtag' not found: %v", err)
	}

	// "beam_normal_exit" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/jit/beam_jit_main.cpp#L54
	beamNormalExit, _, err := ef.SymbolData("beam_normal_exit", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'beam_normal_exit' not found: %v", err)
	}

	d := &beamData{
		otpRelease:          string(otpRelease[:len(otpRelease)-1]),
		ertsVersion:         string(ertsVersion[:len(ertsVersion)-1]),
		theActiveCodeIndex:  libpf.Address(codeIndex.Address),
		r:                   libpf.Address(r.Address),
		beamNormalExit:      libpf.Address(beamNormalExit.Address),
		ertsAtomTable:       uint64(atomTable.Address),
		etpPtrMask:          nopanicslicereader.Uint64(etpPtrMask, 0),
		etpHeaderSubtagMask: nopanicslicereader.Uint64(etpHeaderSubtagMask, 0),
		etpHeapBitsSubtag:   nopanicslicereader.Uint64(etpHeapBitsSubtag, 0),
	}

	// If erts_frame_layout is not defined, it means that frame pointers are not supported,
	// so use 0 to signify that they're not enabled since that shouldn't be a real offset.
	erts_frame_layout_symbol, _, err := ef.SymbolData("erts_frame_layout", 8)
	if err == nil {
		d.ertsFrameLayout = uint64(erts_frame_layout_symbol.Address)
	} else {
		d.ertsFrameLayout = 0
	}

	vms := &d.vmStructs

	// These values are the same on OTP releases 27.2.4 and 28.0.2.
	vms.ranges.sizeOf = 32
	vms.beamCodeHeader.numFunctions = 0
	vms.beamCodeHeader.lineTable = 72
	vms.ertsCodeInfo.sizeOf = 40
	vms.ertsCodeInfo.mfa = 16
	vms.ertsCodeMfa.module = 0
	vms.ertsCodeMfa.function = 8
	vms.ertsCodeMfa.arity = 16
	vms.beamCodeLineTab.sizeOf = 32
	vms.beamCodeLineTab.fnamePtr = 0
	vms.beamCodeLineTab.locSize = 8
	vms.beamCodeLineTab.locTab = 16
	vms.beamCodeLineTab.funcTab = 24
	vms.indexTable.segTable = 120
	vms.atom.len = 24
	vms.erlHeapBits.data = 16

	switch d.otpRelease {
	case "27":
		vms.beamCodeHeader.sizeOf = 144
		vms.beamCodeHeader.functions = 136
		vms.atom.name = 32
	case "28":
		vms.beamCodeHeader.sizeOf = 160
		vms.beamCodeHeader.functions = 152
		vms.atom.u.bin = 32
	default:
		return d, fmt.Errorf("unsupported OTP version for BEAM interpreter: %s", d.otpRelease)
	}

	return d, nil
}

func (d *beamData) String() string {
	return fmt.Sprintf("BEAM OTP %s, ERTS %s", d.otpRelease, d.ertsVersion)
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Debugf("BEAM attaching, OTP %s, ERTS %s, bias: 0x%x", d.otpRelease, d.ertsVersion, bias)

	data := support.BEAMProcInfo{
		R:                     uint64(bias + d.r),
		The_active_code_index: uint64(bias + d.theActiveCodeIndex),
		Beam_normal_exit:      uint64(bias + d.beamNormalExit),
		Ranges_sizeof:         uint8(d.vmStructs.ranges.sizeOf),
	}

	// If this value is zero, it means that frame pointer support is not included in the runtime binary
	if d.ertsFrameLayout != 0 {
		ertsFrameLayout := rm.Uint64(bias + libpf.Address(d.ertsFrameLayout))
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_vm.h#L68-L73
		data.Frame_pointers_enabled = ertsFrameLayout == 1
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
		prefixes:    make(map[lpm.Prefix]uint32),
		rangesPtr:   bias + libpf.Address(d.r),
		atomTable:   bias + libpf.Address(d.ertsAtomTable),
		atomCache:   make(map[uint32]string),
		stringCache: stringCache,
	}, nil
}

func (d *beamData) Unload(_ interpreter.EbpfHandler) {
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler, _ reporter.ExecutableReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	i.mappingGeneration++
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || !m.IsAnonymous() {
			continue
		}

		// Just assume all anonymous and executable mappings are BEAM for now
		log.Debugf("Enabling BEAM for %#x/%#x", m.Vaddr, m.Length)

		prefixes, err := lpm.CalculatePrefixList(m.Vaddr, m.Vaddr+m.Length)
		if err != nil {
			return fmt.Errorf("new anonymous mapping lpm failure %#x/%#x", m.Vaddr, m.Length)
		}

		for _, prefix := range prefixes {
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
		log.Debugf("Delete BEAM prefix %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(i.prefixes, prefix)
	}

	return nil
}

func (i *beamInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	return nil
}

func (i *beamInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames) error {
	if !ef.Type().IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}
	pc := libpf.Address(ef.Data())
	codeHeader := libpf.Address(ef.Variable(0))

	log.Debugf("BEAM symbolizing pc: 0x%x", pc)

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

	numFunctions := i.rm.Uint32(codeHeader + libpf.Address(vms.beamCodeHeader.numFunctions))
	functions := codeHeader + libpf.Address(vms.beamCodeHeader.functions)

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

			mfa := ertsCodeInfo + libpf.Address(vms.ertsCodeInfo.mfa)
			moduleID := i.rm.Uint32(mfa + libpf.Address(vms.ertsCodeMfa.module))
			functionID := i.rm.Uint32(mfa + libpf.Address(vms.ertsCodeMfa.function))
			arity := i.rm.Uint32(mfa + libpf.Address(vms.ertsCodeMfa.arity))

			return functionIndex, moduleID, functionID, arity, nil
		}
	}

	return 0, 0, 0, 0, fmt.Errorf("BEAM unable to find the MFA for PC 0x%x in expected code range", pc)
}

func (i *beamInstance) findFileLocation(codeHeader libpf.Address, functionIndex uint64, pc libpf.Address) (fileName libpf.String, lineNumber uint64, err error) {
	vms := i.data.vmStructs

	lineTable := i.rm.Ptr(codeHeader + libpf.Address(vms.beamCodeHeader.lineTable))
	functionTable := lineTable + libpf.Address(vms.beamCodeLineTab.funcTab)

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
			locSize := i.rm.Uint32(lineTable + libpf.Address(vms.beamCodeLineTab.locSize))
			locTab := i.rm.Ptr(lineTable + libpf.Address(vms.beamCodeLineTab.locTab))
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

	segTable := i.rm.Ptr(i.atomTable + libpf.Address(vms.indexTable.segTable))
	segment := i.rm.Ptr(segTable + libpf.Address(8*(index>>16)))
	entry := i.rm.Ptr(segment + libpf.Address(8*((index>>6)&0x3FF)))

	len := i.rm.Uint16(entry + libpf.Address(vms.atom.len))

	name := make([]byte, len)
	switch i.data.otpRelease {
	case "27":
		err := i.rm.Read(i.rm.Ptr(entry+libpf.Address(vms.atom.name)), name)
		if err != nil {
			return "", fmt.Errorf("BEAM Unable to lookup atom with index %d: %v", index, err)
		}
	case "28":
		// Implementation based on https://github.com/erlang/otp/blob/OTP-28.0.2/erts/etc/unix/etp-commands.in#L657-L674
		unboxed := i.rm.Ptr(entry+libpf.Address(vms.atom.u.bin)) & libpf.Address(i.data.etpPtrMask)

		subtag := i.rm.Uint64(unboxed) & uint64(i.data.etpHeaderSubtagMask)
		if subtag == uint64(i.data.etpHeapBitsSubtag) {
			err := i.rm.Read(unboxed+libpf.Address(vms.erlHeapBits.data), name)
			if err != nil {
				return "", fmt.Errorf("BEAM Unable to lookup atom with index %d (ErlHeapBits tag): %v", index, err)
			}
		} else {
			return "", fmt.Errorf("BEAM Unable to lookup atom with index %d: expected boxed value subtag 0x%x, found 0x%x", index, i.data.etpHeapBitsSubtag, subtag)
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
		charAddr := eterm & libpf.Address(i.data.etpPtrMask)
		charValue := i.rm.Uint64(charAddr)
		char := uint8(charValue >> 4)
		result.WriteByte(char)
		length++
		nextAddr := libpf.Address((eterm & libpf.Address(i.data.etpPtrMask)) + 8)
		eterm = libpf.Address(i.rm.Uint64(nextAddr))
	}

	if length > maxLength {
		result.WriteString("...")
	}

	value := libpf.Intern(result.String())
	i.stringCache.Add(eterm, value)

	return value
}
