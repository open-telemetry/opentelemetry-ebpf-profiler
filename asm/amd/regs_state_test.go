package amd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
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
	it := NewInterpreter(code)
	it.CodeAddress = variable.Imm(0x8AF05)

	err := it.Loop()
	if err == nil || err != io.EOF {
		t.Fatal(err)
	}
	actual := it.Regs.Get(x86asm.RAX)
	expected := variable.Mem(
		variable.Add(
			variable.Mul(
				variable.Crop(variable.Mem(variable.Any()), 8),
				variable.Imm(8),
			),
			variable.Var("switch table"),
		),
	)
	if !actual.Eval(expected) {
		t.Fatal()
	}
}

func FuzzInterpreter(f *testing.F) {
	f.Fuzz(func(_ *testing.T, code []byte) {
		i := NewInterpreter(code)
		_ = i.Loop()
	})
}

func TestDebugPrinting(t *testing.T) {
	assert.False(t, debugPrinting)
}
