// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// BEAM VM Unwinder support code

// The BEAM VM is an interpreter for Erlang, as well as several other languages
// that share the same bytecode, such as Elixir and Gleam.

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
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
	beamRegex                        = regexp.MustCompile(`beam.smp`)
	_           interpreter.Data     = &beamData{}
	_           interpreter.Instance = &beamInstance{}
	BogusFileID                      = libpf.NewFileID(0xf00d, 0x1001)
)

type beamData struct {
	version               uint32
	the_active_code_index uint64
	r                     uint64
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid          libpf.PID
	bias         libpf.Address
	data         *beamData
	rm           remotememory.RemoteMemory
	rangesPtr    libpf.Address
	codeIndexPtr libpf.Address
	// mappings is indexed by the Mapping to its generation
	mappings map[process.Mapping]*uint32
	// prefixes is indexed by the prefix added to ebpf maps (to be cleaned up) to its generation
	prefixes map[lpm.Prefix]*uint32
	// mappingGeneration is the current generation (so old entries can be pruned)
	mappingGeneration uint32
}

type beamRange struct {
	start libpf.Address
	end   libpf.Address
}

type beamRanges struct {
	modules   *beamRange
	n         uint64
	allocated uint64
	mid       libpf.Address
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
	log.Infof("BEAM interpreter found: %v", matches)

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

	interpRanges, err := info.GetSymbolAsRanges(libpf.SymbolName("process_main"))
	if err != nil {
		return nil, err
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindBEAM, info.FileID(), interpRanges); err != nil {
		return nil, err
	}

	// "the_active_code_index" and "r" symbols are from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	the_active_code_index, err := ef.LookupSymbolAddress("the_active_code_index")
	if err != nil {
		return nil, fmt.Errorf("symbol 'the_active_code_index' not found: %v", err)
	}

	r, err := symbols.LookupSymbolAddress(libpf.SymbolName("r"))
	if err != nil {
		return nil, fmt.Errorf("symbol 'r' not found: %v", err)
	}

	log.Infof("BEAM r address: %x", r)

	d := &beamData{
		version:               otpVersion,
		the_active_code_index: uint64(the_active_code_index),
		r:                     uint64(r),
	}

	log.Infof("BEAM loaded %v", d)

	return d, nil
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Infof("BEAM interpreter attaching, bias: %x", bias)

	data := C.BEAMProcInfo{
		version: C.u32(d.version),
		bias:    C.u64(bias),
	}
	if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}

	return &beamInstance{
		pid:          pid,
		bias:         bias,
		data:         d,
		rm:           rm,
		rangesPtr:    bias + libpf.Address(d.r),
		codeIndexPtr: bias + libpf.Address(d.the_active_code_index),
		mappings:     make(map[process.Mapping]*uint32),
		prefixes:     make(map[lpm.Prefix]*uint32),
	}, nil
}

func (i *beamInstance) SynchronizeMappingsFromBEAMRanges(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()

	codeIndex := i.rm.Uint64(i.codeIndexPtr)
	activeRanges := i.rangesPtr + libpf.Address(32*codeIndex)

	n := i.rm.Uint64(activeRanges + libpf.Address(8))

	low := i.rm.Ptr(i.rm.Ptr(activeRanges))
	high := i.rm.Ptr(i.rm.Ptr(activeRanges) + libpf.Address(16*n) + 8)

	log.Infof("Enabling BEAM for %#x - %#x", low, high)
	prefixes, err := lpm.CalculatePrefixList(uint64(low), uint64(high))
	if err != nil {
		return fmt.Errorf("new anonymous mapping lpm failure %#x - %#x", low, high)
	}
	for _, prefix := range prefixes {
		err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindBEAM, 0, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	i.mappingGeneration++
	for idx := range mappings {
		m := &mappings[idx]

		if !m.IsExecutable() {
			continue
		}

		// log.Infof("Synchronizing executable Mapping %#x/%#x", m.Vaddr, m.Length)

		if !m.IsAnonymous() {
			continue
		}

		if _, exists := i.mappings[*m]; exists {
			*i.mappings[*m] = i.mappingGeneration
			continue
		}

		// Generate a new uint32 pointer which is shared for mapping and the prefixes it owns
		// so updating the mapping above will reflect to prefixes also.
		mappingGeneration := i.mappingGeneration
		i.mappings[*m] = &mappingGeneration

		log.Infof("Enabling BEAM for range %#x/%#x", m.Vaddr, m.Length)

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
			i.prefixes[prefix] = &mappingGeneration
		}
	}

	// Remove prefixes not seen
	for prefix, generationPtr := range i.prefixes {
		if *generationPtr == i.mappingGeneration {
			continue
		}
		log.Infof("Delete prefix %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(i.prefixes, prefix)
	}
	for m, generationPtr := range i.mappings {
		if *generationPtr == i.mappingGeneration {
			continue
		}
		log.Infof("Disabling mapping for %#x/%#x", m.Vaddr, m.Length)
		delete(i.mappings, m)
	}

	return nil
}

func (i *beamInstance) SynchronizeMappingsFromJITDump(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	file, err := os.Open(fmt.Sprintf("/tmp/jit-%d.dump", uint32(pid)))
	if err != nil {
		return err
	}
	defer file.Close()

	header, err := ReadJITDumpHeader(file)
	if err != nil {
		return err
	}
	log.Infof("Parsed header: %v", *header)

	for recordHeader, err := ReadJITDumpRecordHeader(file); err == nil; recordHeader, err = ReadJITDumpRecordHeader(file) {
		switch recordHeader.ID {
		case JITCodeLoad:
			record, name, err := ReadJITDumpRecordCodeLoad(file, recordHeader)
			if err != nil {
				return err
			}

			log.Infof("JITDump Code Load %s @ 0x%x (%d bytes)", name, record.CodeAddr, record.CodeSize)

			prefixes, err := lpm.CalculatePrefixList(record.CodeAddr, record.CodeAddr+record.CodeSize)
			if err != nil {
				return fmt.Errorf("lpm failure %#x/%#x", record.CodeAddr, record.CodeSize)
			}

			for _, prefix := range prefixes {
				// TODO: Include FileID
				err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindBEAM, 0, 0)
				if err != nil {
					return err
				}
			}

			// TODO: remove mappings that have been moved/unloaded

		default:
			log.Warnf("Ignoring JITDump record type %d", recordHeader.ID)
			SkipJITDumpRecord(file, recordHeader)
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
	// Index into the active static `r` variable using the currently-active code index (the size of the `ranges` struct is 32 bytes)
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	codeIndex := i.rm.Uint64(i.codeIndexPtr)
	activeRanges := i.rangesPtr + libpf.Address(32*codeIndex)

	// Use offsets into the `ranges` struct to get the beginning of the array and the number of entries based on
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
	modules := i.rm.Ptr(activeRanges)
	n := i.rm.Uint64(activeRanges + libpf.Address(8))

	pc := libpf.Address(frame.Lineno)

	log.Infof("BEAM symbolizing pc: %x, n: %d", pc, n)

	low := i.rm.Ptr(modules)
	high := i.rm.Ptr(modules + libpf.Address((n-1)*16+8))

	if pc >= low && pc <= high {
		// Get a pointer to both the target `BeamCodeHeader` struct and the one following it,
		// because we will want the last field in the struct, which is the pointer to the `functions` table,
		// but the size of the struct depends on configuration, so we hack around that by using a negative offset from the next struct,
		// since they'll be adjacent in memory.
		codeHeader := libpf.Address(0)
		lowIdx := uint64(0)
		highIdx := n - 1
		for lowIdx < highIdx {
			midIdx := lowIdx + (highIdx-lowIdx)/2
			// Each `Range` entry is 16 bytes: a pointer to the `start` and a pointer to the `end`
			// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L31-L34
			midStart := i.rm.Ptr(modules + libpf.Address(midIdx*16))
			midEnd := i.rm.Ptr(modules + libpf.Address(midIdx*16+8))
			if pc < midStart {
				highIdx = midIdx
			} else if pc >= midEnd {
				lowIdx = midIdx + 1
			} else {
				log.Warnf("BEAM found the correct range: idx: %d, start: %x, end: %x", midIdx, midStart, midEnd)
				codeHeader = midStart
				break
			}
		}

		// `codeHeader` points to `BeamCodeHeader` struct, defined here:
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L56-L125
		// Need to figure out a better way to maintain offsets for the `functions` field, but for now...
		// (gdb) set var $hdr=(BeamCodeHeader*)(r[the_active_code_index.counter].modules[3].start)
		// (gdb) ptype/o $hdr
		// type = struct beam_code_header {
		//      0      |       8     UWord num_functions;
		//      8      |       8     const byte *attr_ptr;
		//     16      |       8     UWord attr_size;
		//     24      |       8     UWord attr_size_on_heap;
		//     32      |       8     const byte *compile_ptr;
		//     40      |       8     UWord compile_size;
		//     48      |       8     UWord compile_size_on_heap;
		//     56      |       8     struct ErtsLiteralArea_ *literal_area;
		//     64      |       8     const ErtsCodeInfo *on_load;
		//     72      |       8     const BeamCodeLineTab *line_table;
		//     80      |       8     Uint coverage_mode;
		//     88      |       8     void *coverage;
		//     96      |       8     byte *line_coverage_valid;
		//    104      |       8     Uint32 *loc_index_to_cover_id;
		//    112      |       8     Uint line_coverage_len;
		//    120      |       8     const byte *md5_ptr;
		//    128      |       8     byte *are_nifs;
		//    136      |       8     const ErtsCodeInfo *functions[1];
		// total size (bytes):  144
		// }

		// `functions` is a pointer to an array of `ErtsCodeInfo` structs, defined here:
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L104-L123
		// (gdb) ptype/o $hdr.functions
		// type = const struct ErtsCodeInfo_ {
		// 	/*      0      |       8 */    struct {
		// 	/*      0      |       8 */        struct {
		// 	/*      0      |       7 */            char raise_function_clause[7];
		// 	/*      7      |       1 */            char breakpoint_flag;
		//
		// 										   /* total size (bytes):    8 */
		// 									   } metadata;
		//
		// 									   /* total size (bytes):    8 */
		// 								   } u;
		// 	/*      8      |       8 */    struct GenericBp *gen_bp;
		// 	/*     16      |      24 */    ErtsCodeMFA mfa;
		//
		// 								   /* total size (bytes):   40 */

		numFunctions := i.rm.Uint32(codeHeader)
		log.Infof("BEAM module has %d functions", numFunctions)

		for idx := range numFunctions {
			ertsCodeInfo := i.rm.Ptr(codeHeader + libpf.Address(136+idx*8))

			module := i.rm.Uint32(ertsCodeInfo + libpf.Address(16))
			function := i.rm.Uint32(ertsCodeInfo + libpf.Address(16+8))
			arity := i.rm.Uint32(ertsCodeInfo + libpf.Address(16+16))
			log.Warnf("BEAM functions[%d]: %d.%d/%d", idx, module, function, arity)
		}

	}

	return nil
}
