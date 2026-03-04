// // Copyright The OpenTelemetry Authors
// // SPDX-License-Identifier: Apache-2.0

package gpu_test

// import (
// 	"testing"
// 	"unique"
// 	"unsafe"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// 	"github.com/zeebo/xxh3"

// 	"go.opentelemetry.io/ebpf-profiler/host"
// 	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
// 	"go.opentelemetry.io/ebpf-profiler/libpf"
// 	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
// 	"go.opentelemetry.io/ebpf-profiler/support"
// )

// // TestProgramNamesExist verifies that the eBPF program names used in cuda.go
// // actually exist in the compiled eBPF collection. This catches bugs where
// // the program names don't match the SEC() names in the .ebpf.c files.
// func TestProgramNamesExist(t *testing.T) {
// 	// Load the eBPF collection
// 	coll, err := support.LoadCollectionSpec()
// 	require.NoError(t, err, "Failed to load eBPF collection spec")

// // Verify single-shot program names exist
// t.Run("SingleShotPrograms", func(t *testing.T) {
// 	progNames := []string{
// 		gpu.USDTProgCudaCorrelation,
// 		gpu.USDTProgCudaKernel,
// 		gpu.USDTProgCudaActivityBatch,
// 		gpu.USDTProgCudaActivityBatchTail,
// 	}

// 		for _, progName := range progNames {
// 			t.Run(progName, func(t *testing.T) {
// 				prog := coll.Programs[progName]
// 				require.NotNil(t, prog, "eBPF program %q not found in collection", progName)
// 				t.Logf("Found program %q", progName)
// 			})
// 		}
// 	})

// 	// Verify multi-attach program name exists
// 	t.Run("MultiAttachProgram", func(t *testing.T) {
// 		prog := coll.Programs[gpu.USDTProgCudaProbe]
// 		require.NotNil(t, prog, "eBPF program %q not found in collection", gpu.USDTProgCudaProbe)
// 		t.Logf("Found program %q", gpu.USDTProgCudaProbe)
// 	})
// }

// // computeTraceHash replicates the hash logic from tracer.loadBpfTrace:
// // zero per-sample fields, then hash the raw bytes.
// func computeTraceHash(tr *support.Trace) host.TraceHash {
// 	// Work on a copy so we don't mutate the caller's data.
// 	clone := *tr
// 	clone.ZeroPerSampleFields()
// 	raw := unsafe.Slice((*byte)(unsafe.Pointer(&clone)), unsafe.Sizeof(clone))
// 	return host.TraceHash(xxh3.Hash128(raw).Lo)
// }

// // makeCUDATrace builds a support.Trace with one CUDA kernel frame (at position 0)
// // followed by nativFrames native frames. The CUDA frame encodes the given
// // correlationID and cbid.
// func makeCUDATrace(pid uint32, correlationID uint32, cbid int32,
// 	nativeFrames []support.Frame) support.Trace {
// 	tr := support.Trace{
// 		Pid:             pid,
// 		Tid:             pid,
// 		Origin:          support.TraceOriginCuda,
// 		Kernel_stack_id: -1, // no kernel stack
// 	}

// 	// CUDA kernel frame first (matches BPF collect_trace ordering).
// 	cudaID := uint64(correlationID) | (uint64(uint32(cbid)) << 32)
// 	tr.Frames[0] = support.Frame{
// 		Kind:         support.FrameMarkerCUDAKernel,
// 		Addr_or_line: cudaID,
// 	}
// 	tr.Stack_len = 1

// 	for i, f := range nativeFrames {
// 		tr.Frames[1+i] = f
// 		tr.Stack_len++
// 	}

// 	return tr
// }

// func TestCUDATraceHashStability(t *testing.T) {
// 	// Two launches from the same call site (identical native frames)
// 	// with different correlation IDs must produce the same hash.
// 	nativeFrames := []support.Frame{
// 		{File_id: 0xaaaa, Addr_or_line: 0x1000, Kind: 8}, // native
// 		{File_id: 0xaaaa, Addr_or_line: 0x2000, Kind: 8}, // native
// 		{File_id: 0xbbbb, Addr_or_line: 0x3000, Kind: 8}, // native
// 	}

// 	tr1 := makeCUDATrace(100, 42, 1, nativeFrames)
// 	tr2 := makeCUDATrace(100, 999, 1, nativeFrames)

// 	hash1 := computeTraceHash(&tr1)
// 	hash2 := computeTraceHash(&tr2)
// 	assert.Equal(t, hash1, hash2,
// 		"same call site with different correlation IDs should produce identical hashes")

// 	// Different CBID (different API call type) with same native stack should
// 	// also produce the same hash since cbid is part of addr_or_line.
// 	tr3 := makeCUDATrace(100, 42, 7, nativeFrames)
// 	hash3 := computeTraceHash(&tr3)
// 	assert.Equal(t, hash1, hash3,
// 		"same call site with different CBIDs should produce identical hashes")
// }

// func TestCUDATraceHashDiffers(t *testing.T) {
// 	framesA := []support.Frame{
// 		{File_id: 0xaaaa, Addr_or_line: 0x1000, Kind: 8},
// 	}
// 	framesB := []support.Frame{
// 		{File_id: 0xaaaa, Addr_or_line: 0x2000, Kind: 8}, // different addr
// 	}

// 	trA := makeCUDATrace(100, 42, 1, framesA)
// 	trB := makeCUDATrace(100, 42, 1, framesB)

// 	hashA := computeTraceHash(&trA)
// 	hashB := computeTraceHash(&trB)
// 	assert.NotEqual(t, hashA, hashB,
// 		"different native stacks should produce different hashes")
// }

// func TestCUDATraceHashExcludesPerSampleFields(t *testing.T) {
// 	frames := []support.Frame{
// 		{File_id: 0xaaaa, Addr_or_line: 0x1000, Kind: 8},
// 	}

// 	tr1 := makeCUDATrace(100, 42, 1, frames)
// 	tr2 := makeCUDATrace(100, 42, 1, frames)

// 	// Vary all the per-sample fields that should be excluded.
// 	tr2.Ktime = 99999
// 	tr2.Origin = support.TraceOriginOffCPU
// 	tr2.Offtime = 12345
// 	tr2.Comm = [16]byte{'d', 'i', 'f', 'f', 'e', 'r', 'e', 'n', 't'}

// 	hash1 := computeTraceHash(&tr1)
// 	hash2 := computeTraceHash(&tr2)
// 	assert.Equal(t, hash1, hash2,
// 		"per-sample fields (ktime, origin, offtime, comm) must not affect hash")
// }

// func TestNonCUDATraceHashIncludesAddrOrLine(t *testing.T) {
// 	// For non-CUDA frames, addr_or_line MUST be included in the hash.
// 	makeNative := func(addr uint64) support.Trace {
// 		tr := support.Trace{
// 			Pid:             100,
// 			Tid:             100,
// 			Origin:          support.TraceOriginSampling,
// 			Stack_len:       1,
// 			Kernel_stack_id: -1,
// 		}
// 		tr.Frames[0] = support.Frame{
// 			File_id:      0xaaaa,
// 			Addr_or_line: addr,
// 			Kind:         8, // native
// 		}
// 		return tr
// 	}

// 	tr1 := makeNative(0x1000)
// 	tr2 := makeNative(0x2000)

// 	hash1 := computeTraceHash(&tr1)
// 	hash2 := computeTraceHash(&tr2)
// 	assert.NotEqual(t, hash1, hash2,
// 		"non-CUDA traces with different addresses must have different hashes")
// }

// // makeSymbolizedTrace builds a libpf.Trace that looks like what ConvertTrace
// // produces for a CUDA trace: frames before cudaFrameIdx are native, then the
// // CUDAKernelFrame, then more native frames.
// func makeSymbolizedTrace(cudaFrameIdx int, nativeFrameCount int) *libpf.Trace {
// 	trace := &libpf.Trace{}
// 	for i := range cudaFrameIdx + 1 + nativeFrameCount {
// 		if i == cudaFrameIdx {
// 			trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
// 				Type: libpf.CUDAKernelFrame,
// 			}))
// 		} else {
// 			trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
// 				Type:            libpf.NativeFrame,
// 				AddressOrLineno: libpf.AddressOrLineno(0x1000 * (i + 1)),
// 				FileID:          libpf.NewFileID(uint64(i+1), 0),
// 			}))
// 		}
// 	}
// 	return trace
// }

// func TestAddTraceAndTimes(t *testing.T) {
// 	const pid = libpf.PID(500)
// 	gpu.RegisterTestFixer(pid)
// 	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

// 	// Simulate: trace arrives first, timing arrives second.
// 	trace := makeSymbolizedTrace(0, 2) // CUDA frame at index 0
// 	meta := &samples.TraceEventMeta{PID: pid}

// 	st := &gpu.SymbolizedCudaTrace{
// 		Trace:         trace,
// 		Meta:          meta,
// 		CUDAFrameIdx:  0,
// 		CorrelationID: 100,
// 		CBID:          1,
// 	}

// 	// AddTrace with no pending timing -> stored, no outputs.
// 	outputs := gpu.AddTrace(st)
// 	assert.Empty(t, outputs, "no timing yet, should produce no outputs")

// 	// Now timing arrives.
// 	kernelName := [256]byte{}
// 	copy(kernelName[:], "_Z9myKernelPfS_i")

// 	events := []gpu.CuptiTimingEvent{{
// 		Pid:        uint32(pid),
// 		Id:         100,
// 		Start:      1000,
// 		End:        2000,
// 		Dev:        0,
// 		Stream:     7,
// 		KernelName: kernelName,
// 	}}

// 	outputs = gpu.AddTimes(events)
// 	require.Len(t, outputs, 1, "timing matched, should produce one output")

// 	out := outputs[0]
// 	assert.Equal(t, int64(1000), out.Meta.OffTime, "OffTime should be End-Start")
// 	assert.Equal(t, "0", out.Trace.CustomLabels["cuda_device"])
// 	assert.Equal(t, "7", out.Trace.CustomLabels["cuda_stream"])

// 	// Verify the CUDA frame got the kernel name and zeroed AddressOrLineno.
// 	cudaFrame := out.Trace.Frames[0].Value()
// 	assert.Equal(t, libpf.CUDAKernelFrame, cudaFrame.Type)
// 	assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno,
// 		"correlation ID should be zeroed in output")
// 	assert.Equal(t, "_Z9myKernelPfS_i", cudaFrame.FunctionName.String())
// }

// func TestAddTimeThenTrace(t *testing.T) {
// 	const pid = libpf.PID(501)
// 	gpu.RegisterTestFixer(pid)
// 	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

// 	// Simulate: timing arrives first, trace arrives second.
// 	kernelName := [256]byte{}
// 	copy(kernelName[:], "_Z6squarePfS_")

// 	events := []gpu.CuptiTimingEvent{{
// 		Pid:        uint32(pid),
// 		Id:         200,
// 		Start:      5000,
// 		End:        8000,
// 		Dev:        1,
// 		KernelName: kernelName,
// 	}}

// 	// Timing arrives first -> stored, no outputs.
// 	outputs := gpu.AddTimes(events)
// 	assert.Empty(t, outputs)

// 	// Now trace arrives and matches.
// 	trace := makeSymbolizedTrace(0, 1)
// 	meta := &samples.TraceEventMeta{PID: pid}

// 	st := &gpu.SymbolizedCudaTrace{
// 		Trace:         trace,
// 		Meta:          meta,
// 		CUDAFrameIdx:  0,
// 		CorrelationID: 200,
// 		CBID:          1,
// 	}

// 	outputs = gpu.AddTrace(st)
// 	require.Len(t, outputs, 1)

// 	out := outputs[0]
// 	assert.Equal(t, int64(3000), out.Meta.OffTime)
// 	assert.Equal(t, "1", out.Trace.CustomLabels["cuda_device"])

// 	cudaFrame := out.Trace.Frames[0].Value()
// 	assert.Equal(t, "_Z6squarePfS_", cudaFrame.FunctionName.String())
// 	assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno)
// }

// func TestCachedTemplateWithDifferentCorrelationIDs(t *testing.T) {
// 	const pid = libpf.PID(502)
// 	gpu.RegisterTestFixer(pid)
// 	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

// 	// Simulate two launches from the same call site (same template) with
// 	// different correlation IDs and different kernel names from timing.
// 	// This is the scenario where the cache provides the template.
// 	template := makeSymbolizedTrace(0, 2)

// 	for _, tc := range []struct {
// 		corrID     uint32
// 		kernelName string
// 		offTime    int64
// 	}{
// 		{corrID: 300, kernelName: "_Z7kernelAv", offTime: 100},
// 		{corrID: 301, kernelName: "_Z7kernelBv", offTime: 200},
// 	} {
// 		meta := &samples.TraceEventMeta{PID: pid}

// 		st := &gpu.SymbolizedCudaTrace{
// 			Trace:         template,
// 			Meta:          meta,
// 			CUDAFrameIdx:  0,
// 			CorrelationID: tc.corrID,
// 			CBID:          1,
// 		}
// 		gpu.AddTrace(st)

// 		kn := [256]byte{}
// 		copy(kn[:], tc.kernelName)
// 		outputs := gpu.AddTimes([]gpu.CuptiTimingEvent{{
// 			Pid:        uint32(pid),
// 			Id:         tc.corrID,
// 			Start:      0,
// 			End:        uint64(tc.offTime),
// 			KernelName: kn,
// 		}})
// 		require.Len(t, outputs, 1, "corrID %d should produce one output", tc.corrID)

// 		out := outputs[0]
// 		assert.Equal(t, tc.offTime, out.Meta.OffTime)

// 		cudaFrame := out.Trace.Frames[0].Value()
// 		assert.Equal(t, libpf.AddressOrLineno(0), cudaFrame.AddressOrLineno,
// 			"correlation ID must not leak into output")
// 		// Verify each launch got its own kernel name.
// 		assert.Equal(t, tc.kernelName, cudaFrame.FunctionName.String(),
// 			"each launch should get its own kernel name")
// 	}
// }

// func TestCUDAFrameIdxNonZero(t *testing.T) {
// 	const pid = libpf.PID(503)
// 	gpu.RegisterTestFixer(pid)
// 	t.Cleanup(func() { gpu.UnregisterTestFixer(pid) })

// 	// CUDA frame at index 2 (after two kernel/native frames).
// 	trace := makeSymbolizedTrace(2, 2) // [native, native, CUDA, native, native]
// 	meta := &samples.TraceEventMeta{PID: pid}

// 	kernelName := [256]byte{}
// 	copy(kernelName[:], "_Z4testv")

// 	st := &gpu.SymbolizedCudaTrace{
// 		Trace:         trace,
// 		Meta:          meta,
// 		CUDAFrameIdx:  2,
// 		CorrelationID: 400,
// 		CBID:          1,
// 	}
// 	gpu.AddTrace(st)

// 	outputs := gpu.AddTimes([]gpu.CuptiTimingEvent{{
// 		Pid:        uint32(pid),
// 		Id:         400,
// 		Start:      0,
// 		End:        500,
// 		KernelName: kernelName,
// 	}})
// 	require.Len(t, outputs, 1)

// 	// The CUDA frame at index 2 should have the kernel name.
// 	cudaFrame := outputs[0].Trace.Frames[2].Value()
// 	assert.Equal(t, libpf.CUDAKernelFrame, cudaFrame.Type)
// 	assert.Equal(t, "_Z4testv", cudaFrame.FunctionName.String())

// 	// The non-CUDA frames should be untouched.
// 	for _, idx := range []int{0, 1, 3, 4} {
// 		f := outputs[0].Trace.Frames[idx].Value()
// 		assert.Equal(t, libpf.NativeFrame, f.Type,
// 			"frame %d should remain native", idx)
// 	}
// }
