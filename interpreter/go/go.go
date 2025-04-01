// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

/*
#cgo CFLAGS: -g -Wall
#include "../../rust-crates/symblib-capi/c/symblib.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"hash/fnv"
	"runtime"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
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
	exec string
}

type goInstance struct {
	interpreter.InstanceStubs

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	goRuntime *C.SymblibPointResolver
	pin       runtime.Pinner
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

	exec, err := info.ExtractAsFile()
	if err != nil {
		return nil, err
	}

	return &goData{
		exec: exec,
	}, nil
}

func (g *goData) Attach(_ interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	gi := &goInstance{}

	executablePath := C.CString(g.exec)
	defer C.free(unsafe.Pointer(executablePath))

	//nolint:gocritic
	status := C.symblib_goruntime_new(executablePath, &gi.goRuntime)
	if status != C.SYMBLIB_OK {
		return nil, fmt.Errorf("failed to create point resolver for '%s': %d",
			C.GoString(executablePath), status)
	}
	gi.pin.Pin(unsafe.Pointer(&gi.goRuntime))

	return gi, nil
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

func (g *goInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	if g.goRuntime != nil {
		g.pin.Unpin()
		C.symblib_goruntime_free(g.goRuntime)
		g.goRuntime = nil
	}
	return nil
}

func (g *goInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame,
	trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	sfCounter := successfailurecounter.New(&g.successCount, &g.failCount)
	defer sfCounter.DefaultToFailure()

	if g.goRuntime == nil {
		return errors.New("point resolver is out of scope")
	}

	var symbols *C.SymblibSlice_SymblibResolvedSymbol
	defer C.symblib_slice_symblibresolved_symbol_free(symbols)

	//nolint:gocritic
	status := C.symblib_point_resolver_symbols_for_pc(g.goRuntime,
		C.uint64_t(frame.Lineno), &symbols)
	if status != C.SYMBLIB_OK {
		return fmt.Errorf("failed to do point lookup at 0x%x: %d",
			frame.Lineno, status)
	}

	// Access resolved symbols
	symbolsSlice := unsafe.Slice((*C.SymblibResolvedSymbol)(unsafe.Pointer(symbols.data)),
		symbols.len)
	if len(symbolsSlice) != 1 {
		return fmt.Errorf("unexpected return for point lookup: %d", len(symbolsSlice))
	}

	lineNo := libpf.SourceLineno(symbolsSlice[0].line_number)
	funcName := C.GoString(symbolsSlice[0].function_name)
	sourceFile := C.GoString(symbolsSlice[0].file_name)

	// The fnv hash Write() method calls cannot fail, so it's safe to ignore the errors.
	h := fnv.New128a()
	_, _ = h.Write([]byte(frame.File.StringNoQuotes()))
	_, _ = h.Write([]byte(funcName))
	_, _ = h.Write([]byte(sourceFile))
	fileID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("failed to create a file ID: %v", err)
	}

	frameID := libpf.NewFrameID(fileID, libpf.AddressOrLineno(lineNo))

	trace.AppendFrameID(libpf.GoFrame, frameID)

	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: funcName,
		SourceFile:   sourceFile,
		SourceLine:   lineNo,
	})
	sfCounter.ReportSuccess()
	return nil
}
