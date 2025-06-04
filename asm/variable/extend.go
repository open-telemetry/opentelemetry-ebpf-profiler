// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"
import (
	"fmt"
	"math"
)

var _ Expression = &extend{}

func SignExtend(v Expression, bits int) Expression {
	return &extend{v, bits, true}
}
func ZeroExtend(v Expression, bits int) Expression {
	if bits >= 64 {
		bits = 64
	}
	c := &extend{
		v:    v,
		bits: bits,
	}
	if c.bits == 0 {
		return Imm(0)
	}
	if c.bits == 64 {
		return c.v
	}
	switch typed := c.v.(type) {
	case *immediate:
		return Imm(typed.Value & c.MaxValue())
	case *extend:
		if typed.sign {
			return c
		}
		if typed.bits <= c.bits {
			return typed
		}
		return &extend{typed.v, c.bits, false}
	default:
		myMax := c.MaxValue()
		vMax := c.v.MaxValue()
		if vMax <= myMax {
			return c.v
		}
		return c
	}
}

type extend struct {
	v    Expression
	bits int
	sign bool
}

func (c *extend) MaxValue() uint64 {
	if c.bits >= 64 || c.sign {
		return math.MaxUint64
	}
	return 1<<c.bits - 1
}

func (c *extend) Match(v Expression) bool {
	switch typed := v.(type) {
	case *extend:
		return typed.bits == c.bits && typed.sign == c.sign && c.v.Match(typed.v)
	case *Variable:
		if typed.isAny {
			typed.extracted = c
			return true
		}
		return false
	default:
		return false
	}
}

func (c *extend) DebugString() string {
	s := "zero"
	if c.sign {
		s = "sign"
	}
	return fmt.Sprintf("%s-extend(%s, %d bits)", s, c.v, c.bits)
}
