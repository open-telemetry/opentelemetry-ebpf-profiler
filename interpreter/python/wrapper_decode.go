// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"
	"runtime"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func decodeStubArgumentWrapper(
	code []byte,
	codeAddress libpf.SymbolValue,
	memoryBase libpf.SymbolValue,
) (libpf.SymbolValue, error) {
	switch runtime.GOARCH {
	case "arm64":
		return decodeStubArgumentARM64(code, memoryBase), nil
	case "amd64":
		return decodeStubArgumentAMD64(code, uint64(codeAddress), uint64(memoryBase))
	default:
		return libpf.SymbolValueInvalid, fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
}
