// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// BEAM VM Unwinder support code

// The BEAM VM is an interpreter for Erlang, as well as several other languages
// that share the same bytecode, such as Elixir and Gleam.

import (
	"fmt"
	"regexp"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
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
	otpRelease  string
	ertsVersion string
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid  libpf.PID
	data *beamData
	rm   remotememory.RemoteMemory
	bias libpf.Address

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

	d := &beamData{
		otpRelease:  string(otpRelease[:len(otpRelease)-1]),
		ertsVersion: string(ertsVersion[:len(ertsVersion)-1]),
	}

	return d, nil
}

func (d *beamData) String() string {
	return fmt.Sprintf("BEAM OTP %s, ERTS %s", d.otpRelease, d.ertsVersion)
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Debugf("BEAM attaching, OTP %s, ERTS %s, bias: 0x%x", d.otpRelease, d.ertsVersion, bias)

	data := support.BEAMProcInfo{
		Bias: uint64(bias),
	}

	if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}

	return &beamInstance{
		pid:      pid,
		data:     d,
		rm:       rm,
		bias:     bias,
		prefixes: make(map[lpm.Prefix]uint32),
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

func (r *beamInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames) error {
	if !ef.Type().IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}

	frames.Append(&libpf.Frame{
		Type:       libpf.BEAMFrame,
		SourceFile: libpf.Intern("Unknown File"),
		SourceLine: libpf.SourceLineno(ef.Data()),
	})

	return nil
}
