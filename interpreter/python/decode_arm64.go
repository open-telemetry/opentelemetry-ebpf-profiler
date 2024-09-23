//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
)

func decodeStubArgumentWrapper(code []byte, argNumber uint8, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	return decodeStubArgumentWrapperARM64(code, argNumber, symbolValue, addrBase)
}
