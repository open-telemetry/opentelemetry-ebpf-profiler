// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"debug/gosym"
	"errors"
	"fmt"
	"hash/fnv"
	"sync/atomic"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

var (
	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &goData{}
	_ interpreter.Instance = &goInstance{}
)

type goData struct {
	pclnData []byte
	symTable *gosym.Table
}

type goInstance struct {
	interpreter.InstanceStubs

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	d *goData
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (
	interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	if !ef.IsGolang() {
		return nil, nil
	}

	pclnData, err := elfunwindinfo.SearchGoPclntab(ef)
	if err != nil {
		return nil, err
	}
	if pclnData == nil {
		return nil, errors.New("failed to identify .gopclntab")
	}

	runtimeTextAddr := uint64(0)

	textSec := ef.Section(".text")
	if textSec != nil {
		runtimeTextAddr = textSec.Addr
	} else {
		// Fallback via symbols lookup:
		//nolint:govet
		sm, err := ef.ReadDynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("failed to read symbols table: %v", err)
		}
		sm.VisitAll(func(s libpf.Symbol) {
			if s.Name == "runtime.text" {
				runtimeTextAddr = uint64(s.Address)
			}
		})
	}

	if runtimeTextAddr == 0 {
		return nil, errors.New("failed to get address of runtime.text")
	}

	// Avoid race conditions where the mmaped backed data is no longer
	// available but we try to symbolize Go frames.
	cpy := make([]byte, len(pclnData))
	copy(cpy, pclnData)
	gD := &goData{pclnData: cpy}

	pcln := gosym.NewLineTable(gD.pclnData, runtimeTextAddr)
	if pcln == nil {
		return nil, errors.New("failed to create Line Table from .gopclntab")
	}

	gD.symTable, err = gosym.NewTable(nil, pcln)
	if err != nil {
		return nil, err
	}

	return gD, nil
}

func (g *goData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &goInstance{
		d: g,
	}, nil
}

// Unload is a NOP for goData.
func (g *goData) Unload(_ interpreter.EbpfHandler) {
}

func (g *goInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{
		{
			ID:    metrics.IDGoSymbolizationSuccess,
			Value: metrics.MetricValue(g.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDGoSymbolizationFailure,
			Value: metrics.MetricValue(g.failCount.Swap(0)),
		},
	}, nil
}

// Detach is a NOP for goInstance.
func (g *goInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (g *goInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame,
	trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	sfCounter := successfailurecounter.New(&g.successCount, &g.failCount)
	defer sfCounter.DefaultToFailure()

	sourceFile, lineNo, fn := g.d.symTable.PCToLine(uint64(frame.Lineno))
	if fn == nil {
		return fmt.Errorf("failed to symbolize 0x%x", frame.Lineno)
	}

	// The fnv hash Write() method calls cannot fail, so it's safe to ignore the errors.
	h := fnv.New128a()
	_, _ = h.Write([]byte(frame.File.StringNoQuotes()))
	_, _ = h.Write([]byte(fn.Name))
	_, _ = h.Write([]byte(sourceFile))
	fileID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("failed to create a file ID: %v", err)
	}

	frameID := libpf.NewFrameID(fileID, libpf.AddressOrLineno(lineNo))

	trace.AppendFrameID(libpf.GoFrame, frameID)

	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: fn.Name,
		SourceFile:   sourceFile,
		SourceLine:   libpf.SourceLineno(lineNo),
	})

	sfCounter.ReportSuccess()
	return nil
}
