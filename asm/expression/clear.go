// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"

import (
	"fmt"
)

type clear struct {
	v    Expression
	bits uint
}

// int must be nonnegative
func mask(bits uint) uint64 {
	return (uint64(1) << bits) - 1
}

// Clear returns an expression with the least-significant
// bits cleared; for example, Clear(expr, 16) would model
// expr & ^0xFFFF
func Clear(v Expression, bits uint) Expression {
	if bits >= 64 {
		bits = 64
	}
	if bits == 0 {
		return v
	}
	switch typed := v.(type) {
	case *immediate:
		return Imm(typed.Value & ^mask(bits))
	case *clear:
		return Clear(typed.v, max(typed.bits, bits))
	default:
		return &clear{v, bits}
	}
}

func (c *clear) Match(pattern Expression) bool {
	if typed, ok := pattern.(*clear); ok && typed.bits == c.bits && c.v.Match(typed.v) {
		return true
	}
	return false
}

func (c *clear) DebugString() string {
	if c.bits == 0 {
		// shouldn't happen; we should have simplified Clear(expr, 0) to expr.
		// But do something sensible here just in case.
		return fmt.Sprintf("(%s) & ^0x0 [no-op!]", c.v.DebugString())
	}
	return fmt.Sprintf("(%s) & ^%#x", c.v.DebugString(), mask(c.bits))
}
