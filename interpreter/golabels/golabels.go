// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"fmt"
	"go/version"
	"unsafe"

	log "github.com/sirupsen/logrus"

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

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if err := ebpf.UpdateProcData(libpf.GoLabels, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *data) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.GoLabels, pid)
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

	if version.Compare(goVersion, "go1.25") >= 0 {
		return nil, fmt.Errorf("unsupported Go version %s (need >= 1.13 and <= 1.24)", goVersion)
	}

	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)

	offsets := getOffsets(goVersion)
	tlsOffset, err := extractTLSGOffset(file)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TLS offset: %w", err)
	}
	offsets.Tls_offset = tlsOffset

	return &data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}
