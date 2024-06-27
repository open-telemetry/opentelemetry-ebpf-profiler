//go:build amd64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package python

import (
	"unsafe"

	"github.com/elastic/otel-profiling-agent/libpf"
	_ "github.com/elastic/otel-profiling-agent/zydis" // links Zydis
)

// #cgo CFLAGS: -g -Wall
// #include "decode_amd64.h"
// #include "../../support/ebpf/types.h"
import "C"

func decodeStubArgumentWrapperX64(code []byte, argNumber uint8, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	return libpf.SymbolValue(C.decode_stub_argument(
		(*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)),
		C.uint8_t(argNumber), C.uint64_t(symbolValue), C.uint64_t(addrBase)))
}

func decodeStubArgumentWrapper(code []byte, argNumber uint8, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	return decodeStubArgumentWrapperX64(code, argNumber, symbolValue, addrBase)
}
