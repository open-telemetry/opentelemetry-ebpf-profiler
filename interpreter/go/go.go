// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"debug/elf"
	"errors"
	"fmt"
	"go/version"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &goData{}
	_ interpreter.Instance = &goInstance{}
)

type goData struct {
	fileID    host.FileID
	goVersion string
	offsets   support.GoRuntimeOffsets

	pclntab *elfunwindinfo.Gopclntab
	// refs only tracks the pclntab lifetime.
	// without it there is nothing to reference-count.
	refs atomic.Int32
}

type goInstance struct {
	interpreter.InstanceStubs
	d *goData

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64
}

var errDecodeSymbol = errors.New("failed to decode symbol")
var errRuntimeIsCgoUnavailable = errors.New("runtime.iscgo value unavailable")

func (d *goData) unref() {
	if d.pclntab == nil {
		return
	}
	if d.refs.Add(-1) == 0 {
		_ = d.pclntab.Close()
	}
}

func (d *goData) String() string {
	return "Go " + d.goVersion
}

func (d *goData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if err := ebpf.UpdateProcData(libpf.Go, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}
	if d.pclntab != nil {
		d.refs.Add(1)
	}
	return &goInstance{d: d}, nil
}

func (i *goInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	err := ebpf.DeleteProcData(libpf.Go, pid)
	i.d.unref()
	return err
}

func (d *goData) Unload(_ interpreter.EbpfHandler) {
	d.unref()
}

func GetLoader(cfg Config) interpreter.Loader {
	return func(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (
		interpreter.Data, error) {
		return loader(cfg, info)
	}
}

func loader(cfg Config, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	file, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	goVersion, err := file.GoVersion()
	if err != nil {
		return nil, err
	}
	if goVersion == "" {
		log.Debugf("file %s is not a Go binary", info.FileName())
		return nil, nil
	}

	// Go plugins are shared objects that share the runtime with the main
	// binary. The offsets we need are determined by the main binary so there
	// is no reason to create a duplicate instance for a plugin. A shared
	// library is ET_DYN without a PT_INTERP segment (PIE executables are also
	// ET_DYN but have PT_INTERP).
	if file.Type == elf.ET_DYN {
		hasInterp := false
		for i := range file.Progs {
			if file.Progs[i].Type == elf.PT_INTERP {
				hasInterp = true
				break
			}
		}
		if !hasInterp {
			log.Debugf("file %s is a Go shared library, skipping", info.FileName())
			return nil, nil
		}
	}

	if version.Compare(goVersion, "go1.28") >= 0 {
		return nil, fmt.Errorf("unsupported Go version %s (need >= 1.13 and <= 1.27)", goVersion)
	}

	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)

	offsets := getOffsets(goVersion)
	tlsOffset, err := extractTLSGOffset(file)
	switch {
	case errors.Is(err, libpf.ErrSymbolNotFound):
		return nil, fmt.Errorf("failed to lookup symbol in %s: %v", info.FileName(), err)
	case errors.Is(err, errDecodeSymbol), errors.Is(err, errRuntimeIsCgoUnavailable):
		log.Warnf("In %s: %v", info.FileName(), err)
	case errors.Is(err, nil):
		// Nothing to do - just continue
	default:
		return nil, fmt.Errorf("failed to extract TLS offset: %w", err)
	}
	offsets.Tls_offset = tlsOffset

	d := &goData{
		fileID:    info.FileID(),
		goVersion: goVersion,
		offsets:   offsets,
	}
	if !cfg.IsSymbolizationDisabled() {
		pclntab, err := elfunwindinfo.NewGopclntab(file)
		if err != nil {
			return nil, err
		}
		d.pclntab = pclntab
		d.refs.Store(1)
	}
	return d, nil
}
