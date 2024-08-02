/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

// This file contains Go functions exported to the C ebpf code. This needs to be
// in separate file:
// Using //export in a file places a restriction on the preamble: since it is copied
// into two different C output files, it must not contain any definitions, only
// declarations. If a file contains both definitions and declarations, then the two
// output files will produce duplicate symbols and the linker will fail. To avoid
// this, definitions must be placed in preambles in other files, or in C source files.

import (
	"encoding/hex"
	"math/bits"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/support"
	"github.com/elastic/otel-profiling-agent/util"

	log "github.com/sirupsen/logrus"
)

/*
#define TESTING_COREDUMP
#include "../../support/ebpf/types.h"
#include "../../support/ebpf/extmaps.h"
*/
import "C"

//export __bpf_log
func __bpf_log(buf unsafe.Pointer, sz C.int) {
	log.Info(string(sliceBuffer(buf, sz)))
}

//export __push_frame
func __push_frame(id, file, line C.u64, frameType, returnAddress C.uchar) C.int {
	ctx := ebpfContextMap[id]

	ctx.trace.Frames = append(ctx.trace.Frames, host.Frame{
		File:          host.FileID(file),
		Lineno:        libpf.AddressOrLineno(line),
		Type:          libpf.FrameType(frameType),
		ReturnAddress: returnAddress != 0,
	})

	return C.ERR_OK
}

//export bpf_ktime_get_ns
func bpf_ktime_get_ns() C.ulonglong {
	return C.ulonglong(util.GetKTime())
}

//export bpf_get_current_comm
func bpf_get_current_comm(buf unsafe.Pointer, sz C.int) C.int {
	copy(sliceBuffer(buf, sz), "comm")
	return 0
}

//export __bpf_probe_read_user
func __bpf_probe_read_user(id C.u64, buf unsafe.Pointer, sz C.int, ptr unsafe.Pointer) C.long {
	ctx := ebpfContextMap[id]
	dst := sliceBuffer(buf, sz)
	if _, err := ctx.remoteMemory.ReadAt(dst, int64(uintptr(ptr))); err != nil {
		return -1
	}
	return 0
}

// stackDeltaInnerMap is a special map returned to C code to indicate that
// we are accessing one of nested maps in the exe_id_to_X_stack_deltas maps
var stackDeltaInnerMap = &C.bpf_map_def{
	key_size: 8,
}

//export __bpf_map_lookup_elem
func __bpf_map_lookup_elem(id C.u64, mapdef *C.bpf_map_def, keyptr unsafe.Pointer) unsafe.Pointer {
	ctx := ebpfContextMap[id]
	switch mapdef {
	case &C.pid_page_to_mapping_info:
		key := (*C.PIDPage)(keyptr)
		for key.prefixLen >= support.BitWidthPID {
			if val, ok := ctx.pidToPageMapping[*key]; ok {
				return val
			}
			key.prefixLen--
			shiftBits := support.BitWidthPID + support.BitWidthPage - key.prefixLen
			mask := uint64(0xffffffffffffffff) << shiftBits
			key.page &= C.ulonglong(bits.ReverseBytes64(mask))
		}
	case &C.per_cpu_records:
		return ctx.perCPURecord
	case &C.interpreter_offsets, &C.dotnet_procs, &C.perl_procs, &C.php_procs, &C.py_procs,
		&C.hotspot_procs, &C.ruby_procs, &C.v8_procs:
		var key any
		switch mapdef.key_size {
		case 8:
			key = *(*C.u64)(keyptr)
		case 4:
			key = *(*C.u32)(keyptr)
		}
		if innerMap, ok := ctx.maps[mapdef]; ok {
			if val, ok := innerMap[key]; ok {
				return val
			}
		}
	case &C.stack_delta_page_to_info:
		return ctx.stackDeltaPageToInfo[*(*C.StackDeltaPageKey)(keyptr)]
	case &C.exe_id_to_8_stack_deltas, &C.exe_id_to_9_stack_deltas, &C.exe_id_to_10_stack_deltas,
		&C.exe_id_to_11_stack_deltas, &C.exe_id_to_12_stack_deltas, &C.exe_id_to_13_stack_deltas,
		&C.exe_id_to_14_stack_deltas, &C.exe_id_to_15_stack_deltas, &C.exe_id_to_16_stack_deltas,
		&C.exe_id_to_17_stack_deltas, &C.exe_id_to_18_stack_deltas, &C.exe_id_to_19_stack_deltas,
		&C.exe_id_to_20_stack_deltas, &C.exe_id_to_21_stack_deltas:
		ctx.stackDeltaFileID = *(*C.u64)(keyptr)
		return unsafe.Pointer(stackDeltaInnerMap)
	case &C.unwind_info_array:
		key := uintptr(*(*C.u32)(keyptr))
		return unsafe.Pointer(uintptr(ctx.unwindInfoArray) + key*C.sizeof_UnwindInfo)
	case stackDeltaInnerMap:
		key := uintptr(*(*C.u32)(keyptr))
		if deltas, ok := ctx.exeIDToStackDeltaMaps[ctx.stackDeltaFileID]; ok {
			return unsafe.Pointer(uintptr(deltas) + key*C.sizeof_StackDelta)
		}
	case &C.metrics:
		return unsafe.Pointer(uintptr(0))
	case &C.system_config:
		return ctx.systemConfig
	default:
		log.Errorf("Map at 0x%x not found (looking up key '%v')",
			mapdef, hex.Dump(sliceBuffer(keyptr, C.int(mapdef.key_size))))
	}
	return unsafe.Pointer(uintptr(0))
}
