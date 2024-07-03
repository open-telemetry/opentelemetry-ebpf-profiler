//go:build amd64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tpbase

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"

	_ "github.com/elastic/otel-profiling-agent/zydis" // links Zydis
)

// #cgo CFLAGS: -g -Wall
// #include <stdlib.h>
// #include "fsbase_decode_amd64.h"
import "C"

func x86GetAnalyzers() []Analyzer {
	return []Analyzer{
		{"x86_fsbase_write_task", AnalyzeX86fsbaseWriteTask},
		{"aout_dump_debugregs", AnalyzeAoutDumpDebugregs},
	}
}

func GetAnalyzers() []Analyzer {
	return x86GetAnalyzers()
}

// AnalyzeAoutDumpDebugregs looks at the assembly of the `aout_dump_debugregs` function in the
// kernel in order to compute the offset of `fsbase` into `task_struct`.
func AnalyzeAoutDumpDebugregs(code []byte) (uint32, error) {
	if len(code) == 0 {
		return 0, errors.New("empty code blob passed to getFSBaseOffset")
	}

	// Because different compilers generate code that looks different enough, we disassemble the
	// function in order to properly analyze the code and deduce the fsbase offset.
	// The underlying logic uses the zydis library, hence the cgo call.
	offset := uint32(C.decode_fsbase_aout_dump_debugregs(
		(*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code))))

	if offset == 0 {
		return 0, errors.New("unable to determine fsbase offset")
	}

	return offset, nil
}

// AnalyzeX86fsbaseWriteTask looks at the assembly of the function x86_fsbase_write_task which
// is ideal because it only writes the argument to the fsbase function. We can get the fsbase
// offset directly from the assembly here. Available since kernel version 4.20.
func AnalyzeX86fsbaseWriteTask(code []byte) (uint32, error) {
	// Supported sequences (might be surrounded be additional code for the WARN_ONCE):
	//
	// 1) Alpine Linux (kernel 5.10+)
	//    48 89 b7 XX XX XX XX 	mov    %rsi,0xXXXXXXXX(%rdi)

	// No need to disassemble via zydis here, as it's highly unlikely the below machine code
	// matching approach would fail. Indeed, x86-64 calling conventions ensure that:
	// * %rdi is a pointer to a `task_struct` (first parameter)
	// * %rsi == fsbase value (second parameter)
	// the x86_fsbase_write_task function simply sets that task (from the first parameter) fsbase to
	// be equal to the second parameter.
	// See https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process_64.c#L466
	idx := bytes.Index(code, []byte{0x48, 0x89, 0xb7})
	if idx == -1 || idx+7 > len(code) {
		return 0, errors.New("unexpected x86_fsbase_write_task (mov not found)")
	}
	offset := binary.LittleEndian.Uint32(code[idx+3:])
	return offset, nil
}
