package amd

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

func BenchmarkPythonInterpreter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testPythonInterpreter(b)
	}
}

func TestPythonInterpreter(t *testing.T) {
	testPythonInterpreter(t)
}

func testPythonInterpreter(t testing.TB) {
	// 00010000 	4D 89 F2 	mov 	r10, r14
	// 00010003 	45 0F B6 36 	movzx 	r14d, byte ptr [r14]
	// 00010007 	48 8D 05 2D B3 35 00 	lea 	rax, [rip + 0x35b32d]
	// 0001000E 	4C 8B 6C 24 08 	mov 	r13, qword ptr [rsp + 8]
	// 00010013 	48 89 C1 	mov 	rcx, rax
	// 00010016 	48 89 44 24 10 	mov 	qword ptr [rsp + 0x10], rax
	// 0001001B 	45 0F B6 5A 01 	movzx 	r11d, byte ptr [r10 + 1]
	// 00010020 	41 0F B6 C6 	movzx 	eax, r14b
	// 00010024 	48 8B 04 C1 	mov 	rax, qword ptr [rcx + rax*8]
	// 00010028 	FF E0 	jmp 	rax
	code := []byte{
		0x4d, 0x89, 0xf2, 0x45, 0x0f, 0xb6, 0x36, 0x48, 0x8d, 0x05, 0x2d, 0xb3, 0x35,
		0x00, 0x4c, 0x8b, 0x6c, 0x24, 0x08, 0x48, 0x89, 0xc1, 0x48, 0x89, 0x44, 0x24,
		0x10, 0x45, 0x0f, 0xb6, 0x5a, 0x01, 0x41, 0x0f, 0xb6, 0xc6, 0x48, 0x8b, 0x04,
		0xc1, 0xff, 0xe0,
	}
	it := NewInterpreterWithCode(code)
	it.CodeAddress = expression.Imm(0x8AF05)

	_, err := it.Loop()
	if err == nil || err != io.EOF {
		t.Fatal(err)
	}
	actual := it.Regs.Get(x86asm.RAX)
	expected := expression.Mem(
		expression.Add(
			expression.Multiply(
				expression.ZeroExtend(expression.Mem(expression.Any(), 8), 8),
				expression.Imm(8),
			),
			expression.Var("switch table"),
		),
		8,
	)
	if !actual.Match(expected) {
		t.Fatal()
	}
}

func TestRecoverSwitchCase(t *testing.T) {
	blocks := []CodeBlock{
		{
			Address: expression.Imm(0x3310E3),
			Code: []byte{0x48, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x89, 0x18, 0x49,
				0x83, 0xc2, 0x02, 0x44, 0x89, 0xe0, 0x83, 0xe0, 0x03, 0x31, 0xdb,
				0x41, 0xf6, 0xc4, 0x04, 0x4c, 0x89, 0x74, 0x24, 0x10, 0x74, 0x08},
		},
		{
			Address: expression.Imm(0x33110a),
			Code: []byte{
				0x4d, 0x89, 0xdc, 0x4d, 0x8d, 0x47, 0xf8, 0x4c, 0x89, 0x7c, 0x24,
				0x60, 0x4d, 0x8b, 0x7f, 0xf8, 0x48, 0x8b, 0x0d, 0x87, 0x06, 0x17,
				0x01, 0x89, 0xc0, 0x48, 0x8d, 0x15, 0x02, 0xe7, 0xc0, 0x00, 0x48,
				0x63, 0x04, 0x82, 0x48, 0x01, 0xd0, 0x4c, 0x89, 0xd5, 0x4d, 0x89,
				0xc5, 0xff, 0xe0,
			},
		},
	}
	t.Run("manual", func(t *testing.T) {
		it := NewInterpreter()
		initR12 := it.Regs.Get(x86asm.R12)
		it.ResetCode(blocks[0].Code, blocks[0].Address)
		_, err := it.Loop()
		require.ErrorIs(t, err, io.EOF)

		expected := expression.ZeroExtend(initR12, 2)
		assertEval(t, it.Regs.Get(x86asm.RAX), expected)
		it.ResetCode(blocks[1].Code, blocks[1].Address)
		_, err = it.Loop()
		require.ErrorIs(t, err, io.EOF)
		table := expression.Var("table")
		base := expression.Var("base")
		expected = expression.Add(
			expression.SignExtend(
				expression.Mem(
					expression.Add(
						expression.Multiply(
							expression.ZeroExtend(initR12, 2),
							expression.Imm(4),
						),
						table,
					),
					4,
				),
				64,
			),
			base,
		)
		assertEval(t, it.Regs.Get(x86asm.RAX), expected)
		assert.EqualValues(t, 0xf3f82c, table.ExtractedValueImm())
		assert.EqualValues(t, 0xf3f82c, base.ExtractedValueImm())
	})
}

func assertEval(t *testing.T, left, right expression.Expression) {
	if !left.Match(right) {
		assert.Fail(t, "failed to eval %s to %s", left.DebugString(), right.DebugString())
		t.Logf("left  %s", left.DebugString())
		t.Logf("right %s", right.DebugString())
	}
}

func FuzzInterpreter(f *testing.F) {
	f.Fuzz(func(_ *testing.T, code []byte) {
		i := NewInterpreterWithCode(code)
		_, _ = i.Loop()
	})
}

func TestMoveSignExtend(t *testing.T) {
	i := NewInterpreterWithCode([]byte{
		0xB8, 0x01, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x04,
		0xB8, 0x02, 0x00, 0x00, 0x00, 0x48, 0x0F, 0xB6,
		0x40, 0x04, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x48,
		0x0F, 0xBF, 0x40, 0x04,
	})
	_, err := i.Loop()
	require.ErrorIs(t, err, io.EOF)
	pattern := expression.SignExtend(expression.Mem(expression.Imm(7), 2), 64)
	require.True(t, i.Regs.Get(x86asm.RAX).Match(pattern))
}

func TestMemory(t *testing.T) {
	it := NewInterpreterWithCode([]byte{
		0x48, 0xC7, 0x04, 0x24, 0xFE, 0xCA, 0x00, 0x00, 0x48, 0x89, 0xE7, 0x48,
		0x8B, 0x3F,
	}).WithMemory()
	_, err := it.Loop()
	require.ErrorIs(t, err, io.EOF)
	rdi := it.Regs.Get(x86asm.RDI)
	expected := expression.Imm(0xcafe)
	require.True(t, rdi.Match(expected))
}

func TestCompareJumpConstraints(t *testing.T) {
	i := NewInterpreterWithCode([]byte{
		0x41, 0x0f, 0xb7, 0x04, 0x24, 0x49, 0x83, 0xc4, 0x02, 0x0f, 0xb6, 0xf4, 0x44,
		0x0f, 0xb6, 0xf8, 0x41, 0x89, 0xf1, 0x41, 0x81, 0xff, 0xa5, 0x00, 0x00, 0x00,
		0x0f, 0x87, 0xbb, 0xab, 0xf1, 0xff, 0x45, 0x89, 0xf8, 0x42, 0xff, 0x24, 0xc5,
		0x40, 0xec, 0x6d, 0x00,
	})
	_, err := i.Loop()
	require.ErrorIs(t, err, io.EOF)
	r8 := i.Regs.Get(x86asm.R8L)
	fmt.Println(r8.DebugString())
	maxValue := i.MaxValue(r8)
	require.EqualValues(t, 0xa5, maxValue)
}
