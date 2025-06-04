// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"
import (
	"fmt"
	"math"
)

var _ U64 = &extend{}

func SignExtend(v U64, bitsSize int) U64 {
	return &extend{v, bitsSize, true}
}
func ZeroExtend(v U64, bitsSize int) U64 {
	if bitsSize >= 64 {
		bitsSize = 64
	}
	c := &extend{
		v:        v,
		bitsSize: bitsSize,
	}
	if c.bitsSize == 0 {
		return Imm(0)
	}
	if c.bitsSize == 64 {
		return c.v
	}
	switch typed := c.v.(type) {
	case *immediate:
		return Imm(typed.Value & c.MaxValue())
	case *extend:
		if typed.sign {
			return c
		}
		//todo sign check
		//todo add tests
		if typed.bitsSize <= c.bitsSize {
			return typed
		}
		return &extend{typed.v, c.bitsSize, false}
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
	v        U64
	bitsSize int
	sign     bool
}

func (c *extend) MaxValue() uint64 {
	if c.bitsSize >= 64 || c.sign {
		return math.MaxUint64
	}
	return 1<<c.bitsSize - 1
}

func (c *extend) Eval(v U64) bool {
	switch typed := v.(type) {
	case *extend:
		return typed.bitsSize == c.bitsSize && typed.sign == c.sign && c.v.Eval(typed.v)
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

func (c *extend) String() string {
	s := "zero"
	if c.sign {
		s = "sign"
	}
	return fmt.Sprintf("%s-extend(%s, %d bits)", s, c.v, c.bitsSize)
}
