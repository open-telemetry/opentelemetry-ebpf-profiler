// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/plugins/go"

import (
	"fmt"
	"sync/atomic"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/plugins"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

var (
	// compiler check to make sure the needed interfaces are satisfied
	_ plugins.Data     = &goData{}
	_ plugins.Instance = &goInstance{}
)

type goData struct {
	refs atomic.Int32

	fileID  host.FileID
	version string

	pclntab *elfunwindinfo.Gopclntab
}

type goInstance struct {
	plugins.InstanceStubs

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	d *goData
}

func Loader(_ plugins.EbpfHandler, info *plugins.LoaderInfo) (
	plugins.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	goVersion, err := ef.GoVersion()
	if goVersion == "" || err != nil {
		return nil, err
	}

	pclntab, err := elfunwindinfo.NewGopclntab(ef)
	if pclntab == nil {
		return nil, err
	}

	g := &goData{
		fileID:  info.FileID(),
		version: goVersion,
		pclntab: pclntab,
	}
	g.refs.Store(1)
	return g, nil
}

func (g *goData) unref() {
	if g.refs.Add(-1) == 0 {
		_ = g.pclntab.Close()
	}
}

func (g *goData) String() string {
	return "Golang symbolizer " + g.version
}

func (g *goData) Attach(_ plugins.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory, cfg plugins.Config) (plugins.Instance, error) {
	if cfg.(plugins.GoConfig).IsDisabled() {
		return nil, plugins.ErrPluginDisabled
	}

	g.refs.Add(1)
	return &goInstance{d: g}, nil
}

func (g *goData) Unload(_ plugins.EbpfHandler) {
	g.unref()
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

func (g *goInstance) Detach(_ plugins.EbpfHandler, _ libpf.PID) error {
	g.d.unref()
	return nil
}

func (g *goInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames, mapping libpf.FrameMapping) error {
	if !ef.Type().IsInterpType(libpf.Native) {
		return plugins.ErrMismatchInterpreterType
	}
	// Skip native frames that do not belong to this Go binary.
	if host.FileID(ef.Variable(0)) != g.d.fileID {
		return plugins.ErrMismatchInterpreterType
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
	return g.d.pclntab.SetDontNeed()
}
