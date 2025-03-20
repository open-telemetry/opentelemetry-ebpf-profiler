//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	_ "go.opentelemetry.io/ebpf-profiler/zydis" // links Zydis
)

// #cgo CFLAGS: -g -Wall
// #include "decode_amd64.h"
// #include "../../support/ebpf/types.h"
import "C"

func decodeStubArgumentWrapperX64(code []byte, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	if len(code) == 0 {
		return 0
	}
	return libpf.SymbolValue(C.decode_stub_argument(
		(*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(symbolValue), C.uint64_t(addrBase)))
}

func decodeStubArgumentWrapper(code []byte, symbolValue, addrBase libpf.SymbolValue) libpf.SymbolValue {
	return decodeStubArgumentWrapperX64(code, symbolValue, addrBase)
}
