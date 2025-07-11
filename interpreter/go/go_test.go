package golang

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// mockReporter implements reporter.SymbolReporter for testing
type mockReporter struct {
	b             *testing.B
	frameMetadata map[libpf.FrameID]*reporter.FrameMetadataArgs
}

func newMockReporter(b *testing.B) *mockReporter {
	return &mockReporter{
		b:             b,
		frameMetadata: make(map[libpf.FrameID]*reporter.FrameMetadataArgs),
	}
}

func (m *mockReporter) CompareFunctionName(fn string) {
	if len(m.frameMetadata) != 1 {
		m.b.Fatalf("Expected a single entry but got %d", len(m.frameMetadata))
	}
	for _, v := range m.frameMetadata {
		// The returned anonymous function has the suffic 'func1'.
		// Therefore check only for a matching prefix.
		if !strings.HasPrefix(v.FunctionName, fn) {
			m.b.Fatalf("Expected '%s()' but got '%s()'", fn, v.FunctionName)
		}
	}
}

func (m *mockReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	m.frameMetadata[args.FrameID] = args
}

func (m *mockReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	// Not used in this test
}

func (m *mockReporter) FrameKnown(frameID libpf.FrameID) bool {
	_, exists := m.frameMetadata[frameID]
	return exists
}

func (m *mockReporter) ExecutableKnown(fileID libpf.FileID) bool {
	return false
}

func BenchmarkGolang(b *testing.B) {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		b.Fatal("Failed to get PC from runtime")
	}
	fn := runtime.FuncForPC(pc)
	exec, err := os.Executable()
	if err != nil {
		b.Fatalf("Failed to get the executable: %v", err)
	}

	libpfPID := libpf.PID(os.Getpid())
	pid := process.New(libpfPID, libpfPID)

	elfRef := pfelf.NewReference(exec, pid)
	hostFileID, err := host.FileIDFromBytes([]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	if err != nil {
		b.Fatalf("Failed to create hostID: %v", err)
	}
	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, []util.Range{})
	rm := remotememory.NewProcessVirtualMemory(libpfPID)
	symReporter := newMockReporter(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		gD, err := Loader(nil, loaderInfo)
		if err != nil {
			b.Fatalf("Failed to create loader: %v", err)
		}

		gI, err := gD.Attach(nil, libpfPID, 0x0, rm)
		if err != nil {
			b.Fatalf("Failed to create instance: %v", err)
		}

		trace := libpf.Trace{}

		if err := gI.Symbolize(symReporter, &host.Frame{
			File:   hostFileID,
			Lineno: libpf.AddressOrLineno(pc),
			Type:   libpf.FrameType(libpf.Native),
		}, &trace); err != nil {
			b.Fatalf("Failed to symbolize 0x%x: %v", pc, err)
		}

		symReporter.CompareFunctionName(fn.Name())
	}
}
