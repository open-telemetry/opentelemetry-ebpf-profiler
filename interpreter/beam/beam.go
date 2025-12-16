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

	"go.opentelemetry.io/ebpf-profiler/host"
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
	otpRelease         string
	ertsVersion        string
	theActiveCodeIndex libpf.Address
	r                  libpf.Address
	beamNormalExit     libpf.Address
	ertsFrameLayout    uint64

	// Sizes and offsets BEAM internal structs we need to traverse
	vmStructs struct {
		// ranges
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
		ranges struct {
			sizeOf uint8
		}
	}
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid  libpf.PID
	data *beamData
	rm   remotememory.RemoteMemory

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

	// "beam_normal_exit" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/jit/beam_jit_main.cpp#L54
	beamNormalExit, _, err := ef.SymbolData("beam_normal_exit", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'beam_normal_exit' not found: %v", err)
	}

	d := &beamData{
		otpRelease:         string(otpRelease[:len(otpRelease)-1]),
		ertsVersion:        string(ertsVersion[:len(ertsVersion)-1]),
		theActiveCodeIndex: libpf.Address(codeIndex.Address),
		r:                  libpf.Address(r.Address),
		beamNormalExit:     libpf.Address(beamNormalExit.Address),
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

	// This is the same on OTP releases 27.2.4 and 28.0.2.
	vms.ranges.sizeOf = 32

	if d.otpRelease != "27" && d.otpRelease != "28" {
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

	return &beamInstance{
		pid:      pid,
		data:     d,
		rm:       rm,
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

func (i *beamInstance) Symbolize(frame *host.Frame, frames *libpf.Frames) error {
	if !frame.Type.IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}

	frames.Append(&libpf.Frame{
		Type:            libpf.BEAMFrame,
		AddressOrLineno: frame.Lineno,
	})

	return nil
}
