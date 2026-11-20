// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// variableDataDecoder walks a record's variable data region; returned
// slices alias it.
type variableDataDecoder struct {
	raw []byte
	pos uint16
}

func (vd *variableDataDecoder) bytes(end uint16, field string) ([]byte, error) {
	if end == 0 {
		return nil, nil
	}
	if vd.pos > end || int(end) > len(vd.raw) {
		return nil, fmt.Errorf("%s end %d: not in range [%d, %d]: %w",
			field, end, vd.pos, len(vd.raw), ErrRecordUnexpectedSize)
	}
	data := vd.raw[vd.pos:end:end]
	vd.pos = (end + 7) &^ 7
	return data, nil
}

// uint64s returns the section ending at end reinterpreted as uint64 values.
func (vd *variableDataDecoder) uint64s(end uint16, field string) ([]uint64, error) {
	data, err := vd.bytes(end, field)
	if data == nil {
		return nil, err
	}
	n := len(data) / 8
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("%s size %d is not a multiple of 8: %w",
			field, len(data), ErrRecordUnexpectedSize)
	}
	return unsafe.Slice((*uint64)(unsafe.Pointer(unsafe.SliceData(data))), n), nil
}

// decodeTrace parses the copied record into e; its layout was validated by
// HandleTrace.
func (pm *ProcessManager) decodeTrace(e *traceEvent) error {
	raw := e.rawBytes()[:e.recordLen]
	ptr := (*support.Trace)(unsafe.Pointer(unsafe.SliceData(raw)))
	variableData := raw[support.Sizeof_TraceHeader : support.Sizeof_TraceHeader+int(ptr.Variable_data_end)]

	e.Comm = libpf.NewComm(ptr.Comm)
	e.TraceID = *(*libpf.TraceID)(unsafe.Pointer(&ptr.Trace_id))
	e.SpanID = *(*libpf.SpanID)(unsafe.Pointer(&ptr.Span_id))
	e.PID = libpf.PID(ptr.Pid)
	e.TID = libpf.PID(ptr.Tid)
	e.Origin = ptr.Origin
	e.KTime = int64(ptr.Ktime)
	e.CpuID = ptr.Cpu_id
	e.NumFrames = ptr.Num_frames

	vd := variableDataDecoder{raw: variableData}

	// Context values precede the kernel/user frames; empty if absent.
	var err error
	if e.ContextValues, err = vd.uint64s(ptr.Context_value_end, "context value"); err != nil {
		return err
	}
	if e.KernelFrames, err = vd.uint64s(ptr.Kernel_frame_end, "kernel_frame"); err != nil {
		return err
	}
	if e.FrameData, err = vd.uint64s(ptr.Frame_data_end, "frame"); err != nil {
		return err
	}

	goLabelData, err := vd.bytes(ptr.Golang_label_end, "golang label")
	if err != nil {
		return err
	}
	payload, err := vd.bytes(ptr.Thread_label_end, "thread label")
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		decoder := pm.ThreadLabelDecoderForPID(e.PID)
		e.CustomLabels = pm.threadLabels.resolve(payload, decoder)
	}
	// Merge Go labels last so they take precedence on duplicate keys.
	if len(goLabelData) > 0 {
		e.CustomLabels = pm.customLabels.decode(goLabelData, e.CustomLabels)
	}
	return nil
}
