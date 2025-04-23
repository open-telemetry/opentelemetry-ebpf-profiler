// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"
import (
	"fmt"
	"math"
)

var _ U64 = crop{}

func Crop(v U64, sz int) U64 {
	if sz >= 64 {
		sz = 64
	}
	c := crop{
		v:  v,
		sz: sz,
	}
	if c.sz == 0 {
		return Imm(0)
	}
	if c.sz == 64 {
		return c.v
	}
	switch typed := c.v.(type) {
	case immediate:
		return Imm(typed.Value & c.maxValue())
	case crop:
		if typed.sz <= c.sz {
			return typed
		}
		return crop{typed.v, c.sz}
	default:
		myMax := c.maxValue()
		vMax := c.v.maxValue()
		if vMax <= myMax {
			return c.v
		}
	}
	return c
}

type crop struct {
	v  U64
	sz int
}

func (c crop) maxValue() uint64 {
	if c.sz >= 64 {
		return math.MaxUint64
	}
	return 1<<c.sz - 1
}

func (c crop) Eval(v U64) bool {
	switch typed := v.(type) {
	case crop:
		return typed.sz == c.sz && c.v.Eval(typed.v)
	default:
		return false
	}
}

func (c crop) String() string {
	return fmt.Sprintf("crop(%s, %d)", c.v, c.sz)
}
