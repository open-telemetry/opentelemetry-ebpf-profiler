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

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
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
	otp_release, err := readSymbolValue(ef, "etp_otp_release")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read OTP release: %v", err)
	}

	// Slice off the null termination before converting
	otp_major, err := strconv.Atoi(string(otp_release[:len(otp_release)-1]))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse OTP version: %v", err)
	}

	erts_version, err := readSymbolValue(ef, "etp_erts_version")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read erts version: %v", err)
	}

	return uint32(otp_major), erts_version, nil
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

	otp_version, _, err := readReleaseVersion(ef)
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
		version: otp_version,
	}

	log.Infof("BEAM loaded, otp_version: %d, interpRanges: %v", otp_version, interpRanges)
	//d.loadIntrospectionData()

	return d, nil
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Infof("BEAM interpreter attaching")
	return &beamInstance{
		data: d,
		rm:   rm,
	}, nil
}

func (r *beamInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

func (r *beamInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.BEAM) {
		log.Warnf("BEAM failed to symbolize")
		return interpreter.ErrMismatchInterpreterType
	}
	log.Infof("BEAM symbolizing")
	return nil
}
