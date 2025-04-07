// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

// IsEndbr64 returns true if the first 4 bytes of the code is endbr64 instruction
// https://www.felixcloutier.com/x86/endbr64
// The second returned argument is the size of the instruction which is always 4
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
