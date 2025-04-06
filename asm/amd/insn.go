// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

func IsEndbr64(code []byte) (isEndbr bool, size int) {
	if len(code) >= 4 &&
		code[0] == 0xf3 &&
		code[1] == 0x0f &&
		code[2] == 0x1e &&
		code[3] == 0xfa {
		return true, 4
	}
	return false, 0
}
