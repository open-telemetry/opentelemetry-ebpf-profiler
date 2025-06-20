// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"

import (
	"math"
)

var _ Expression = &Variable{}

func Var(name string) *Variable {
	return &Variable{
		name:               name,
		maxValueConstraint: math.MaxUint64,
	}
}

type Variable struct {
	name               string
	maxValueConstraint uint64
	extractedImm       immediate
}

func (v *Variable) ExtractedValueImm() uint64 {
	return v.extractedImm.Value
}

func (v *Variable) MaxValue() uint64 {
	return v.maxValueConstraint
}

func (v *Variable) DebugString() string {
	return "@" + v.name
}

func (v *Variable) Match(pattern Expression) bool {
	switch typedPattern := pattern.(type) {
	case *Variable:
		if typedPattern == v {
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
