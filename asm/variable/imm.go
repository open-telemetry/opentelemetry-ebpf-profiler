// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"
import "fmt"

var zero U64 = &immediate{0}
var one U64 = &immediate{1}

func Imm(v uint64) U64 {
	switch v {
	case 0:
		return zero
	case 1:
		return one
	default:
		return &immediate{v}
	}
}

type immediate struct {
	Value uint64
}

func (v *immediate) MaxValue() uint64 {
	return v.Value
}

func (v *immediate) Simplify() U64 {
	return v
}

func (v *immediate) String() string {
	return fmt.Sprintf("0x%x", v.Value)
}

func (v *immediate) Eval(other U64) bool {
	switch typed := other.(type) {
	case *immediate:
		return v.Value == typed.Value
	case *Variable:
		typed.extracted = v
		return true
	default:
		return false
	}
}
