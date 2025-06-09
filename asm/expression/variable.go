// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"

var _ Expression = &variable{}

func Var(name string) Expression {
	return &variable{
		name: name,
	}
}

type variable struct {
	name string
}

func (v *variable) DebugString() string {
	return "@" + v.name
}

func (v *variable) Match(pattern Expression) bool {
	switch typedPattern := pattern.(type) {
	case *variable:
		return typedPattern == v
	default:
		return false
	}
}
