// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"

import (
	"fmt"
	"math"
)

var _ U64 = &Variable{}

func Any() *Variable {
	v := Var("any")
	v.isAny = true
	return v
}

func Var(name string) *Variable {
	return &Variable{
		extracted:          nil,
		name:               name,
		maxValueConstraint: math.MaxUint64,
		isAny:              false,
	}
}

type Variable struct {
	name               string
	maxValueConstraint uint64
	// if true - extract any U64, if false - extract only immediate
	isAny     bool
	extracted U64
}

func (v *Variable) ExtractedValueImm() uint64 {
	if v.extracted == nil {
		return 0
	}
	imm, ok := v.extracted.(*immediate)
	if ok {
		return imm.Value
	}
	return 0
}

func (v *Variable) MaxValue() uint64 {
	if v.extracted != nil {
		if v.extracted == v {
			return v.maxValueConstraint
		}
		return v.extracted.MaxValue()
	}
	return v.maxValueConstraint
}

func (v *Variable) String() string {
	return fmt.Sprintf("@%s", v.name)
}

func (v *Variable) Eval(other U64) bool {
	switch typed := other.(type) {
	case *Variable:
		if typed.isAny {
			typed.extracted = v
			return true
		}
		if v == typed {
			typed.extracted = v
			return true
		}
		return false
	default:
		return false
	}
}

func (v *Variable) SetMaxValue(i uint64) *Variable {
	v.maxValueConstraint = i
	return v
}
