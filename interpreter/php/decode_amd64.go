//go:build amd64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package php

import (
	"fmt"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/libpf"
	_ "github.com/elastic/otel-profiling-agent/zydis" // links Zydis
)

// #cgo CFLAGS: -g -Wall
// #include "decode_amd64.h"
// #include "../../support/ebpf/types.h"
import "C"

// phpDecodeErrorToString. This function converts an error code
// into a string that corresponds to it.
func phpDecodeErrorToString(errorCode int) string {
	switch errorCode {
	case C.NOT_FOUND_ERROR:
		return "target not found"
	case C.EARLY_RETURN_ERROR:
		return "early return"
	case C.DECODING_ERROR:
		return "decoding error"
	}

	return "unknown error code"
}

// retrieveZendVMKindWrapper. This function reads the code blob and recovers
// the type of the PHP VM that is used by this process.
func retrieveZendVMKindWrapper(code []byte) (uint, error) {
	var vmKind uint
	err := int(C.retrieveZendVMKind((*C.uint8_t)(unsafe.Pointer(&code[0])),
		C.size_t(len(code)), (*C.uint64_t)(unsafe.Pointer(&vmKind))))

	if err == C.NO_ERROR {
		return vmKind, nil
	}

	return 0, fmt.Errorf("failed to decode zend_vm_kind: %s", phpDecodeErrorToString(err))
}

// retrieveExecuteExJumpLabelAddressWrapper. This function reads the code blob and returns
// the address of the return address for any JIT code called from execute_ex. Since all JIT
// code is ultimately called from execute_ex, this is the same as returning the return address
// for all JIT code.
func retrieveExecuteExJumpLabelAddressWrapper(code []byte, addrBase libpf.SymbolValue) (
	libpf.SymbolValue, error) {
	var jumpAddress uint
	err := int(C.retrieveExecuteExJumpLabelAddress((*C.uint8_t)(unsafe.Pointer(&code[0])),
		C.size_t(len(code)), C.uint64_t(addrBase), (*C.uint64_t)(unsafe.Pointer(&jumpAddress))))

	if err == C.NO_ERROR {
		return libpf.SymbolValue(jumpAddress), nil
	}

	return libpf.SymbolValueInvalid,
		fmt.Errorf("failed to decode execute_ex: %s", phpDecodeErrorToString(err))
}

// retrieveJITBufferPtrWrapper. This function reads the code blob and returns a pointer
// to the JIT buffer used by PHP (called "dasm_buf" in the PHP source).
func retrieveJITBufferPtrWrapper(code []byte, addrBase libpf.SymbolValue) (
	dasmBuf libpf.SymbolValue, dasmSize libpf.SymbolValue, err error) {
	var bufferAddress, sizeAddress uint
	err2 := int(C.retrieveJITBufferPtr((*C.uint8_t)(unsafe.Pointer(&code[0])),
		C.size_t(len(code)), C.uint64_t(addrBase),
		(*C.uint64_t)(unsafe.Pointer(&bufferAddress)),
		(*C.uint64_t)(unsafe.Pointer(&sizeAddress))))

	if err2 == C.NO_ERROR {
		return libpf.SymbolValue(bufferAddress), libpf.SymbolValue(sizeAddress), nil
	}

	return libpf.SymbolValueInvalid, libpf.SymbolValueInvalid,
		fmt.Errorf("failed to recover jit buffer: %s", phpDecodeErrorToString(err2))
}
