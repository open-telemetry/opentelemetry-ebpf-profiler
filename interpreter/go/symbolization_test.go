package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"os"
	"runtime"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type fakeSymbolReporter struct {
	functionName string
	sourceFile   string
}

func (sr *fakeSymbolReporter) ExecutableKnown(_ libpf.FileID) bool {
	return false
}
func (sr *fakeSymbolReporter) ExecutableMetadata(_ *reporter.ExecutableMetadataArgs) {}
func (sr *fakeSymbolReporter) FrameKnown(_ libpf.FrameID) bool {
	return false
}
func (sr *fakeSymbolReporter) FrameMetadata(frameMetadata *reporter.FrameMetadataArgs) {
	sr.functionName = frameMetadata.FunctionName
	sr.sourceFile = frameMetadata.SourceFile
}

func Test_Symbolization(t *testing.T) {
	gd := goData{
		exec: "/proc/self/exe",
	}

	pid := libpf.PID(os.Getpid())

	rm := remotememory.NewProcessVirtualMemory(pid)

	gi, err := gd.Attach(nil, pid, libpf.Address(0), rm)
	if err != nil {
		t.Fatalf("failed to attach to Go executable: %v", err)
	}

	sr := &fakeSymbolReporter{}

	pc, file, line, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)

	trace := libpf.Trace{}

	if err := gi.Symbolize(sr, &host.Frame{
		Type:   libpf.NativeFrame,
		Lineno: libpf.AddressOrLineno(pc),
	}, &trace); err != nil {
		t.Fatalf("failed to symbolize Go frame: %v", err)
	}

	if len(trace.FrameTypes) != 1 {
		t.Fatalf("expected 1 frame but got %d", len(trace.FrameTypes))
	}
	if trace.FrameTypes[0] != libpf.GoFrame {
		t.Fatalf("expected Go frame type but got %v", trace.FrameTypes[0])
	}
	if trace.Linenos[0] != libpf.AddressOrLineno(line) {
		t.Fatalf("expected Linenos of %d but got %d", line, trace.Linenos[0])
	}

	if sr.functionName != fn.Name() {
		t.Fatalf("expected '%s' but got '%s'", fn.Name(), sr.functionName)
	}
	if sr.sourceFile != file {
		t.Fatalf("expected '%s' but got '%s", file, sr.sourceFile)
	}
}
