// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

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

func (g *goInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames,
	mapping libpf.FrameMapping) error {
	// pclntab is nil when symbolization is disabled.
	if g.d.pclntab == nil {
		return interpreter.ErrMismatchInterpreterType
	}
	if !ef.Type().IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	// Skip native frames that do not belong to this Go binary.
	if host.FileID(ef.Variable(0)) != g.d.fileID {
		return interpreter.ErrMismatchInterpreterType
	}

	sfCounter := successfailurecounter.New(&g.successCount, &g.failCount)
	defer sfCounter.DefaultToFailure()

	address := ef.Data()
	sourceFile, lineNo, fn := g.d.pclntab.Symbolize(uintptr(address))
	if fn == "" {
		return fmt.Errorf("failed to symbolize 0x%x", address)
	}
	// See comment about return address handling in ProcessManager.convertFrame
	if ef.Flags().ReturnAddress() {
		address--
	}
	frames.Append(&libpf.Frame{
		Type:            libpf.GoFrame,
		AddressOrLineno: libpf.AddressOrLineno(address),
		Mapping:         mapping,
		FunctionName:    libpf.Intern(fn),
		SourceFile:      libpf.Intern(sourceFile),
		SourceLine:      libpf.SourceLineno(lineNo),
	})
	sfCounter.ReportSuccess()
	return nil
}

func (g *goInstance) ReleaseResources() error {
	if g.d.pclntab != nil {
		return g.d.pclntab.SetDontNeed()
	}
	return nil
}
