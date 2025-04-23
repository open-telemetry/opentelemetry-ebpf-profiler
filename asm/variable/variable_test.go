package variable

import (
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVariable(t *testing.T) {
	t.Run("add sort-summ-immediate", func(t *testing.T) {
		v := Var("v")
		assertEqualRecursive(t,
			Add(v, Imm(14)),
			Add(Imm(1), Imm(3), Imm(1), v, Imm(9)),
		)
	})

	t.Run("add 0", func(t *testing.T) {
		v := Var("v")
		assertEqualRecursive(t,
			v,
			Add(Imm(0), v),
		)
	})

	t.Run("add nested", func(t *testing.T) {
		s1 := Var("s1")
		s2 := Var("s2")
		s3 := Var("s3")
		assertEqualRecursive(t,
			Add(Add(s1, s3), s2),
			Add(s1, s3, s2),
		)
		assertEqualRecursive(t,
			Add(Add(s1, s3), s2),
			Add(s2, s3, s1),
		)
	})

	t.Run("add opt", func(t *testing.T) {
		v := Var("v")
		assertEqualRecursive(t,
			Add(Add(Imm(2), v), Imm(7)),
			Add(v, Imm(9)),
		)
	})

	t.Run("add 1 element", func(t *testing.T) {
		assertEqualRecursive(t,
			Add(Imm(2)),
			Imm(2),
		)
	})

	t.Run("mul immediate", func(t *testing.T) {
		v := Var("v")
		assertEqualRecursive(t,
			Mul(v, Imm(27)),
			Mul(Imm(1), Imm(3), Imm(1), v, Imm(9)),
		)
	})

	t.Run("mul 1", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			v,
			Mul(Imm(1), v),
		)
	})

	t.Run("mul add", func(t *testing.T) {
		v1 := Var("v1")
		v2 := Var("v2")
		v3 := Var("v3")
		assertEqualRecursive(t,
			Add(Mul(v1, v3), Mul(v2, v3)),
			Mul(Add(v1, v2), v3),
		)
	})

	t.Run("mul order", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			op{opMul, []U64{v, Imm(239)}},
			Mul(Imm(239), v),
		)
	})

	t.Run("mul 0", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			Imm(0),
			Mul(Imm(0), Imm(3), Imm(1), v, Imm(9)),
		)
	})

	t.Run("xor 0", func(t *testing.T) {
		assertEqualRecursive(t,
			Imm(3),
			Xor(Imm(1), Imm(2)),
		)
	})

	t.Run("xor 3", func(t *testing.T) {
		v1 := Var("v1")
		v2 := Var("v2")
		assertEqualRecursive(t,
			Xor(v1, v2, Imm(3)),
			Xor(v1, v2, Imm(2), Imm(1)),
		)
		assert.NotEqualValues(t,
			Imm(3),
			Xor(v1, v2, Imm(3)),
		)
	})

	t.Run("xor eax, eax", func(t *testing.T) {
		eax := Var("eax")
		assertEqualRecursive(t,
			Imm(0),
			Xor(eax, eax),
		)
	})

	t.Run("crop nested", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			Crop(v, 7),
			Crop(Crop(v, 7), 7),
		)
	})

	t.Run("crop nested smaller", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			Crop(v, 5),
			Crop(Crop(v, 7), 5),
		)
	})
	t.Run("crop nested smaller", func(t *testing.T) {
		v := Var("v")

		assertEqualRecursive(t,
			Crop(v, 5),
			Crop(Crop(v, 5), 7),
		)
	})

	t.Run("crop max1", func(t *testing.T) {
		maxFF := Var("ff").SetMaxValue(0xff)
		assertEqualRecursive(t,
			maxFF,
			Crop(maxFF, 11),
		)
	})

	t.Run("crop max value", func(t *testing.T) {
		maxFF := Var("ff").SetMaxValue(0xff)
		assert.EqualValues(t,
			0b1111111,
			Crop(maxFF, 7).maxValue(),
		)
	})

	t.Run("crop max value", func(t *testing.T) {
		v := Var("v")

		assert.EqualValues(t,
			math.MaxUint32,
			Crop(v, 32).maxValue(),
		)
	})

	t.Run("crop max value", func(t *testing.T) {
		v := Var("v")

		assert.EqualValues(t,
			uint64(math.MaxUint64),
			Crop(v, 64).maxValue(),
		)
	})

	t.Run("add max value overflow", func(t *testing.T) {
		assert.EqualValues(t,
			uint64(math.MaxUint64),
			Add(Var("max64"), Var("max1").SetMaxValue(1)).maxValue(),
		)
	})

	t.Run("any", func(t *testing.T) {
		assert.False(t,
			Any().Eval(Var("v1")),
		)
		assert.True(t,
			Var("v1").Eval(Any()),
		)
	})

	t.Run("crop 0", func(t *testing.T) {
		assert.EqualValues(t,
			0,
			Crop(Var("v1"), 0).maxValue(),
		)
		assertEqualRecursive(t,
			Imm(0),
			Crop(Var("v1"), 0),
		)
	})
}

func assertEqualRecursive(t *testing.T, a, b U64) {
	if !equalRecursive(a, b) {
		t.Errorf("expected %s to be recursive equal to %s", a.String(), b.String())
	}
}
func equalRecursive(a, b U64) bool {
	if ima, aok := a.(immediate); aok {
		if imb, bok := b.(immediate); bok {
			return ima.Value == imb.Value
		}
		return false
	}
	if ima, aok := a.(*Variable); aok {
		if imb, bok := b.(*Variable); bok {
			return ima == imb
		}
		return false
	}
	if ima, aok := a.(mem); aok {
		if imb, bok := b.(mem); bok {
			return ima.segment == imb.segment && equalRecursive(ima.at, imb.at)
		}
		return false
	}
	if ima, aok := a.(crop); aok {
		if imb, bok := b.(crop); bok {
			return ima.sz == imb.sz && equalRecursive(ima.v, imb.v)
		}
		return false
	}
	if ima, aok := a.(op); aok {
		if imb, bok := b.(op); bok {
			return ima.typ == imb.typ && equalOperands(ima.operands, imb.operands)
		}
		return false
	}
	return false
}

func equalOperands(a, b operands) bool {
	if len(a) != len(b) {
		return false
	}
	acopy := make(operands, len(a))
	copy(acopy, a)
	for _, it := range b {
		eq := false
		for j, jit := range acopy {
			if equalRecursive(it, jit) {
				eq = true
				acopy = slices.Delete(acopy, j, j+1)
				break
			}
		}
		if !eq {
			return false
		}
	}
	return len(acopy) == 0
}
