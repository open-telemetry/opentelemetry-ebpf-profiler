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

var (
	// regex for matching the process name
	beamRegex                      = regexp.MustCompile(`beam.smp`)
	_         interpreter.Data     = &beamData{}
	_         interpreter.Instance = &beamInstance{}
)

type beamData struct {
	version uint32
}

type beamInstance struct {
	interpreter.InstanceStubs

	data *beamData
	rm   remotememory.RemoteMemory
	// mappings is indexed by the Mapping to its generation
	mappings map[process.Mapping]*uint32
	// prefixes is indexed by the prefix added to ebpf maps (to be cleaned up) to its generation
	prefixes map[lpm.Prefix]*uint32
	// mappingGeneration is the current generation (so old entries can be pruned)
	mappingGeneration uint32
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

	otpVersion, _, err := readReleaseVersion(ef)
	if err != nil {
		return nil, err
	}

	symbolName := libpf.SymbolName("process_main")
	interpRanges, err := info.GetSymbolAsRanges(symbolName)
	if err != nil {
		return nil, err
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindBEAM, info.FileID(), interpRanges); err != nil {
		return nil, err
	}

	d := &beamData{
		version: otpVersion,
	}

	log.Infof("BEAM loaded, otpVersion: %d, interpRanges: %v", otpVersion, interpRanges)

	return d, nil
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Infof("BEAM interpreter attaching")
	return &beamInstance{
		data:     d,
		rm:       rm,
		mappings: make(map[process.Mapping]*uint32),
		prefixes: make(map[lpm.Prefix]*uint32),
	}, nil
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	i.mappingGeneration++
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || !m.IsAnonymous() {
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

		// Just assume all anonymous and executable mappings are BEAM for now
		log.Infof("Enabling BEAM for %#x/%#x", m.Vaddr, m.Length)

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
		log.Infof("Delete BEAM prefix %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(i.prefixes, prefix)
	}
	for m, generationPtr := range i.mappings {
		if *generationPtr == i.mappingGeneration {
			continue
		}
		log.Infof("Disabling BEAM for %#x/%#x", m.Vaddr, m.Length)
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

	if err != nil {
		return err
	}

	return nil
}

func (i *beamInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	log.Infof("BEAM interpreter detaching")
	return nil
}

func (i *beamInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.BEAM) {
		log.Warnf("BEAM failed to symbolize")
		return interpreter.ErrMismatchInterpreterType
	}
	log.Infof("BEAM symbolizing")
	return nil
}
