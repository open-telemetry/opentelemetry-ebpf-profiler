// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"

import (
	"fmt"
	"math"

	"golang.org/x/arch/x86/x86asm"
)

var _ U64 = &mem{}

func MemS(segment x86asm.Reg, at U64, sizeBytes int) U64 {
	return &mem{at: at, segment: segment, sizeBytes: sizeBytes}
}

func Mem(at U64, sizeBytes int) U64 {
	return &mem{at: at, segment: 0, sizeBytes: sizeBytes}
}

type mem struct {
	segment   x86asm.Reg
	at        U64
	sizeBytes int
}

func (v *mem) MaxValue() uint64 {
	return math.MaxUint64
}

func (v *mem) String() string {
	if v.segment == 0 {
		return fmt.Sprintf("[%s : %d bits]", v.at.String(), v.sizeBytes*8)
	}
	return fmt.Sprintf("[%s : %s : %d bits]", v.segment, v.at.String(), v.sizeBytes*8)
}

func (v *mem) Eval(other U64) bool {
	switch typed := other.(type) {
	case *mem:
		if v.segment != typed.segment {
			return false
		}
		return v.at.Eval(typed.at)
	case *Variable:
		if typed.isAny {
			typed.extracted = v
			return true
		}
		return false
	default:
		return false
	}
}
