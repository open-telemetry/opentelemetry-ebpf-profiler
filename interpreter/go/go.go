// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"fmt"
	"hash/fnv"
	"sync/atomic"

	"github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
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
	pfElf   *pfelf.File
	pclntab *elfunwindinfo.Gopclntab
}

type goInstance struct {
	interpreter.InstanceStubs

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	d *goData

	// addrToFunction provides a cache for faster symbolization of repeating frames.
	addrToFunction *freelru.LRU[libpf.AddressOrLineno, *reporter.FrameMetadataArgs]
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

	pclntab, err := elfunwindinfo.NewGopclntab(ef)
	if pclntab == nil {
		return nil, err
	}

	return &goData{
		pfElf:   ef.Take(),
		pclntab: pclntab,
	}, nil
}

func (g *goData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	addrToFunction, err := freelru.New[libpf.AddressOrLineno, *reporter.FrameMetadataArgs](
		256, func(k libpf.AddressOrLineno) uint32 { return uint32(k) })
	if err != nil {
		return nil, err
	}
	return &goInstance{
		d:              g,
		addrToFunction: addrToFunction,
	}, nil
}

func (g *goData) Unload(_ interpreter.EbpfHandler) {
	_ = g.pfElf.Close()
}

func (g *goInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToFuncStats := g.addrToFunction.ResetMetrics()

	return []metrics.Metric{
		{
			ID:    metrics.IDGoSymbolizationSuccess,
			Value: metrics.MetricValue(g.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDGoSymbolizationFailure,
			Value: metrics.MetricValue(g.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDGoAddrToFuncHit,
			Value: metrics.MetricValue(addrToFuncStats.Hits),
		},
		{
			ID:    metrics.IDGoAddrToFuncMiss,
			Value: metrics.MetricValue(addrToFuncStats.Misses),
		},
		{
			ID:    metrics.IDGoAddrToFuncAdd,
			Value: metrics.MetricValue(addrToFuncStats.Inserts),
		},
		{
			ID:    metrics.IDGoAddrToFuncDel,
			Value: metrics.MetricValue(addrToFuncStats.Removals),
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

	if data, ok := g.addrToFunction.Get(frame.Lineno); ok {
		trace.AppendFrameID(libpf.GoFrame, data.FrameID)
		symbolReporter.FrameMetadata(data)
		sfCounter.ReportSuccess()
		return nil
	}

	sourceFile, lineNo, fn := g.d.pclntab.Symbolize(uintptr(frame.Lineno))
	if fn == "" {
		return fmt.Errorf("failed to symbolize 0x%x", frame.Lineno)
	}

	// The fnv hash Write() method calls cannot fail, so it's safe to ignore the errors.
	h := fnv.New128a()
	_, _ = h.Write([]byte(frame.File.StringNoQuotes()))
	_, _ = h.Write([]byte(fn))
	_, _ = h.Write([]byte(sourceFile))
	fileID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("failed to create a file ID: %v", err)
	}

	frameID := libpf.NewFrameID(fileID, libpf.AddressOrLineno(lineNo))

	g.addrToFunction.Add(frame.Lineno, &reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: fn,
		SourceFile:   sourceFile,
		SourceLine:   libpf.SourceLineno(lineNo),
	})

	trace.AppendFrameID(libpf.GoFrame, frameID)

	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:      frameID,
		FunctionName: fn,
		SourceFile:   sourceFile,
		SourceLine:   libpf.SourceLineno(lineNo),
	})

	sfCounter.ReportSuccess()
	return nil
}
