//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"

import (
	"errors"
	"unsafe"

	_ "go.opentelemetry.io/ebpf-profiler/zydis" // links Zydis
)

// #cgo CFLAGS: -g -Wall
// #include <stdlib.h>
// #include "libc_decode_amd64.h"
import "C"

func ExtractTSDInfoX64_64(code []byte) (TSDInfo, error) {
	// function in order to properly analyze the code and deduce the fsbase offset.
	// The underlying logic uses the zydis library, hence the cgo call.
	val := uint32(C.decode_pthread_getspecific(
		(*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code))))

	if val == 0 {
		return TSDInfo{}, errors.New("unable to determine libc info")
	}

	return TSDInfo{
		Offset:     int16(val & 0xffff),
		Multiplier: uint8(val >> 16),
		Indirect:   uint8((val >> 24) & 1),
	}, nil
}

func ExtractTSDInfoNative(code []byte) (TSDInfo, error) {
	return ExtractTSDInfoX64_64(code)
}
