// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type goFrame struct {
	function, file string
	line           int
}

//go:noinline
func symbolizeCallers() []uintptr {
	pcs := make([]uintptr, 32)
	return pcs[:runtime.Callers(2, pcs)]
}

// These helpers are small enough to be inlined into symbolizeInlineRoot.
func symbolizeInlinedLeaf() []uintptr   { return symbolizeCallers() }
func symbolizeInlinedMiddle() []uintptr { return symbolizeInlinedLeaf() }

//go:noinline
func symbolizeInlineRoot() []uintptr { return symbolizeInlinedMiddle() }

func TestSymbolizeInlinedFrames(t *testing.T) {
	pcs := symbolizeInlineRoot()
	require.GreaterOrEqual(t, len(pcs), 3)
	rootPc := reflect.ValueOf(symbolizeInlineRoot).Pointer()
	if runtime.FuncForPC(pcs[0]).Entry() != rootPc {
		t.Skip("test functions were not inlined")
	}
	// runtime.Callers reports the inlined calls at the return address as the
	// first three PCs.
	var want []goFrame
	runtimeFrames := runtime.CallersFrames(pcs[:3])
	for {
		frame, more := runtimeFrames.Next()
		want = append(want, goFrame{frame.Function, frame.File, frame.Line})
		if !more {
			break
		}
	}
	require.Len(t, want, 3)

	exec, err := os.Executable()
	require.NoError(t, err)
	pid := libpf.PID(os.Getpid())
	hostFileID, err := host.FileIDFromBytes([]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	gD, err := GetLoader(Config{}).Load(nil, interpreter.NewLoaderInfo(hostFileID,
		pfelf.NewReference(exec, process.New(pid, pid)), nil))
	require.NoError(t, err)
	gI, err := gD.Attach(nopEbpf{}, pid, 0x0, remotememory.NewProcessVirtualMemory(pid))
	require.NoError(t, err)

	// The eBPF unwinder reports file addresses, which differ for PIE builds.
	root, err := gI.(*goInstance).d.pclntab.LookupSymbol(libpf.SymbolName(want[2].function))
	require.NoError(t, err)
	returnAddress := uint64(pcs[0] - (rootPc - uintptr(root.Address)))

	symbolize := func(flags libpf.FrameFlags, address uint64) ([]goFrame, error) {
		ef := libpf.NewEbpfFrame(libpf.NativeFrame, flags, 2, address)
		ef[1] = uint64(hostFileID)
		var frames libpf.Frames
		err := gI.Symbolize(ef, &frames, libpf.FrameMapping{})
		var got []goFrame
		for _, uniqueFrame := range frames {
			frame := uniqueFrame.Value()
			assert.Equal(t, libpf.GoFrame, frame.Type)
			// All frames of an address keep the address of the call.
			assert.Equal(t, libpf.AddressOrLineno(returnAddress-1), frame.AddressOrLineno)
			got = append(got, goFrame{frame.FunctionName.String(),
				frame.SourceFile.String(), int(frame.SourceLine)})
		}
		return got, err
	}

	// Return addresses are looked up at the call, which expands to the
	// inlined calls in the order of the Go runtime.
	got, err := symbolize(libpf.FrameFlags(support.FrameFlagReturnAddress), returnAddress)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// Other addresses are looked up as is.
	got, err = symbolize(0, returnAddress-1)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	got, err = symbolize(0, 0)
	require.Error(t, err)
	assert.Empty(t, got)
}
