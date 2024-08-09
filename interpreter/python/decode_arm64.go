//go:build arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package python

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
)

func decodeStubArgumentWrapper(code []byte, argNumber uint8, symbolValue,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	return decodeStubArgumentWrapperARM64(code, argNumber, symbolValue, addrBase)
}
