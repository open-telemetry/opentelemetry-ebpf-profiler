//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func decodeStubArgumentWrapper(code []byte, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	return decodeStubArgumentWrapperARM64(code, 0, symbolValue, addrBase)
}
