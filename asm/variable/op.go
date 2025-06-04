// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"

import (
	"fmt"
	"math"
	"strings"
)

type opType int

const opAdd = opType(1)
const opMul = opType(2)

type op struct {
	typ      opType
	operands operands
}

func newOp(typ opType, operands operands) U64 {
	res := &op{typ: typ, operands: operands}
	return res
}

func (o *op) Eval(other U64) bool {
	switch typed := other.(type) {
	case *op:
		if o.typ != typed.typ || len(o.operands) != len(typed.operands) {
			return false
		}
		return o.operands.Eval(typed.operands)
	case *Variable:
		if typed.isAny {
			typed.extracted = o
			return true
		}
		return false
	default:
		return false
	}
}

func (o *op) String() string {
	ss := make([]string, len(o.operands))
	for i := range o.operands {
		ss[i] = o.operands[i].String()
	}
	sep := ""
	switch o.typ {
	case opAdd:
		sep = "+"
	case opMul:
		sep = "*"
	}
	return fmt.Sprintf("( %s )", strings.Join(ss, sep))
}

func (o *op) MaxValue() uint64 {
	switch o.typ {
	case opAdd:
		return o.maxAddValue()
	default:
		return math.MaxUint64
	}
}
