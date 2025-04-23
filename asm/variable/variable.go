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
		ExtractedValue:     0,
		name:               name,
		maxValueConstraint: math.MaxUint64,
		isAny:              false,
	}
}

type Variable struct {
	ExtractedValue     uint64
	name               string
	maxValueConstraint uint64
	isAny              bool
}

func (v *Variable) maxValue() uint64 {
	return v.maxValueConstraint
}

func (v *Variable) Simplify() U64 {
	return v
}

func (v *Variable) String() string {
	return fmt.Sprintf("{ @%s }", v.name)
}

func (v *Variable) Eval(other U64) bool {
	switch typed := other.(type) {
	case *Variable:
		return v == typed || typed.isAny
	default:
		return false
	}
}

func (v *Variable) SetMaxValue(i uint64) *Variable {
	v.maxValueConstraint = i
	return v
}
