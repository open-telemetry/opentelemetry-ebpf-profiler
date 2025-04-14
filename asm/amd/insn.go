// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"
import "bytes"

// https://www.felixcloutier.com/x86/endbr64
var opcodeEndBr64 = []byte{0xf3, 0x0f, 0x1e, 0xfa}

// DecodeSkippable decodes an instruction that we don't care much about and are going to skip,
// as golang.org/x/arch/x86/x86asm fails to decode it.
// The second returned argument is the size of the decoded instruction to skip.
func DecodeSkippable(code []byte) (ok bool, size int) {
	switch {
	case bytes.HasPrefix(code, opcodeEndBr64):
		return true, len(opcodeEndBr64)
	default:
		return false, 0
	}
}
