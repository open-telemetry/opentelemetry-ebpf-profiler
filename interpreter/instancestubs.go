// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreter // import "go.opentelemetry.io/ebpf-profiler/interpreter"

import (
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// InstanceStubs provides empty implementations of Instance hooks that are
// not mandatory for a Instance implementation.
type InstanceStubs struct {
}

func (is *InstanceStubs) Detach(EbpfHandler, libpf.PID) error {
	return nil
}

func (is *InstanceStubs) SynchronizeMappings(EbpfHandler, reporter.SymbolReporter, process.Process,
	[]process.Mapping) error {
	return nil
}

func (is *InstanceStubs) UpdateTSDInfo(EbpfHandler, libpf.PID, tpbase.TSDInfo) error {
	return nil
}

func (is *InstanceStubs) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{}, nil
}

func (is *InstanceStubs) Symbolize(*host.Frame, *libpf.Frames) error {
	return ErrMismatchInterpreterType
}

type EbpfHandlerStubs struct{}

func (m *EbpfHandlerStubs) UpdatePidInterpreterMapping(_ libpf.PID,
	pfx lpm.Prefix, _ uint8, _ host.FileID, _ uint64) error {
	return nil
}

func (m *EbpfHandlerStubs) DeletePidInterpreterMapping(_ libpf.PID, _ lpm.Prefix) error {
	return nil
}

func (m *EbpfHandlerStubs) CoredumpTest() bool {
	return false
}

func (m *EbpfHandlerStubs) UpdateInterpreterOffsets(uint16, host.FileID,
	[]util.Range) error {
	return nil
}

func (m *EbpfHandlerStubs) UpdateProcData(libpf.InterpreterType, libpf.PID,
	unsafe.Pointer) error {
	return nil
}

func (m *EbpfHandlerStubs) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (mockup *EbpfHandlerStubs) AttachUSDTProbes(libpf.PID, string, string, []pfelf.USDTProbe,
	[]uint64, []string) (LinkCloser, error) {
	return nil, nil
}

func (mockup *EbpfHandlerStubs) UpdateProgArray(string, uint32, string) error {
	return nil
}

func (mockup *EbpfHandlerStubs) AttachUprobe(
	libpf.PID, string, uint64, string) (LinkCloser, error) {
	return nil, nil
}
