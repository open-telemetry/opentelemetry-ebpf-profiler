// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"errors"
	"fmt"
	"go/version"
	"unsafe"

	cebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type data struct {
	goVersion string
	offsets   support.GoLabelsOffsets
	interpreter.InstanceStubs
}

var errDecodeSymbol = errors.New("failed to decode symbol")

func (d *data) String() string {
	return "Golang labels " + d.goVersion
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	if err := ebpf.UpdateProcData(libpf.GoLabels, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *data) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	// Go plugins share the runtime with the main binary, so multiple Go ELF
	// files in the same process produce duplicate golabels instances that all
	// write/delete the same eBPF map entry. Tolerate the key already being
	// removed by another instance.
	err := ebpf.DeleteProcData(libpf.GoLabels, pid)
	if errors.Is(err, cebpf.ErrKeyNotExist) {
		log.Debugf("golabels entry for %d already removed", pid)
		return nil
	}
	return err
}

func (d *data) Unload(_ interpreter.EbpfHandler) {}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
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

	if version.Compare(goVersion, "go1.27") >= 0 {
		return nil, fmt.Errorf("unsupported Go version %s (need >= 1.13 and <= 1.26)", goVersion)
	}

	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)

	offsets := getOffsets(goVersion)
	tlsOffset, err := extractTLSGOffset(file)
	switch {
	case errors.Is(err, libpf.ErrSymbolNotFound):
		return nil, fmt.Errorf("failed to lookup symbol in %s: %v", info.FileName(), err)
	case errors.Is(err, errDecodeSymbol):
		log.Warnf("In %s: %v", info.FileName(), err)
	case errors.Is(err, nil):
		// Nothing to do - just continue
	default:
		return nil, fmt.Errorf("failed to extract TLS offset: %w", err)
	}
	offsets.Tls_offset = tlsOffset

	return &data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}
