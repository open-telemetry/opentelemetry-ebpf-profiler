// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"

import (
	"fmt"
	"math"

	"golang.org/x/arch/x86/x86asm"
)

var _ U64 = mem{}

func MemS(segment x86asm.Reg, at U64) U64 {
	return mem{at: at, segment: segment}
}
func Mem(at U64) U64 {
	return mem{at: at, segment: 0}
}

type mem struct {
	segment x86asm.Reg
	at      U64
}

func (v mem) maxValue() uint64 {
	return math.MaxUint64
}

func (v mem) Simplify() U64 {
	return v
}

func (v mem) String() string {
	if v.segment == 0 {
		return fmt.Sprintf("[ %s ]", v.at.String())
	}
	return fmt.Sprintf("[ %s:%s ]", v.segment, v.at.String())
}

func (v mem) Eval(other U64) bool {
	switch typed := other.(type) {
	case mem:
		if v.segment != typed.segment {
			return false
		}
		return v.at.Eval(typed.at)
	default:
		return false
	}
}
