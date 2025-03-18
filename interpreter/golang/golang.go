// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/golang"

/*
#cgo CFLAGS: -g -Wall
#include "../../rust-crates/symblib-capi/c/symblib.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
)

var (
	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &golangData{}
	_ interpreter.Instance = &golangInstance{}
)

// goSymData caches source information.
type goSymData struct {
	function   string
	sourceFile string
	line       libpf.SourceLineno
}

type golangData struct {
	exec string
}

type golangInstance struct {
	// Golang symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	// pcToFunc is a helper cache ... tdb
	pcToFunc *lru.SyncedLRU[libpf.FrameID, goSymData]

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

	exec := info.FileName()
	if len(exec) < 2 {
		// There are cases where FileName() just returns /.
		// In these cases we can not access the backing executable
		// by FileName() and therefore can not continue here.
		return nil, nil
	}

	return &golangData{
		exec: exec,
	}, nil
}

func (g *golangData) Attach(_ interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	pcToFunc, err := lru.NewSynced[libpf.FrameID, goSymData](1024, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}
	gi := &golangInstance{
		pcToFunc: pcToFunc,
	}

	executablePath := C.CString(fmt.Sprintf("/proc/%d/root%s", pid, g.exec))
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

// SynchronizeMappings is a NOP for Golang.
func (g *golangInstance) SynchronizeMappings(_ interpreter.EbpfHandler, _ reporter.SymbolReporter,
	_ process.Process, _ []process.Mapping) error {
	return nil
}

// UpdateTSDInfo is a NOP for Golang.
func (g *golangInstance) UpdateTSDInfo(_ interpreter.EbpfHandler, _ libpf.PID,
	_ tpbase.TSDInfo) error {
	return nil
}

func (g *golangInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{
		{
			ID:    metrics.IDGolangSymbolizationSuccess,
			Value: metrics.MetricValue(g.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDGolangSymbolizationFailure,
			Value: metrics.MetricValue(g.failCount.Swap(0)),
		},
	}, nil
}

// Detach is a NOP for Golang.
func (g *golangInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	if g.goRuntime != nil {
		g.pin.Unpin()
		C.symblib_goruntime_free(g.goRuntime)
		g.goRuntime = nil
	}
	return nil
}

func (g *golangInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame,
	trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	sfCounter := successfailurecounter.New(&g.successCount, &g.failCount)
	defer sfCounter.DefaultToFailure()

	if g.goRuntime == nil {
		return errors.New("point resolver is out of scope")
	}

	frameID := libpf.NewFrameID(libpf.NewFileID(uint64(frame.File), uint64(frame.File)),
		frame.Lineno)

	if frameInfo, exist := g.pcToFunc.Get(frameID); exist {
		symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
			FrameID:      frameID,
			FunctionName: frameInfo.function,
			SourceFile:   frameInfo.sourceFile,
			SourceLine:   frameInfo.line,
		})
		sfCounter.ReportSuccess()
		return nil
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
	trace.AppendFrameID(libpf.GolangFrame, frameID)

	frameInfo := goSymData{
		function:   C.GoString(symbolsSlice[0].function_name),
		sourceFile: C.GoString(symbolsSlice[0].file_name),
		line:       libpf.SourceLineno(symbolsSlice[0].line_number),
	}

	g.pcToFunc.Add(frameID, frameInfo)

	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: frameInfo.function,
		SourceFile:   frameInfo.sourceFile,
		SourceLine:   frameInfo.line,
	})
	sfCounter.ReportSuccess()
	return nil
}
