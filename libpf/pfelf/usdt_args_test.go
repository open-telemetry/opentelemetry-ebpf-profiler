// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"runtime"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/support/usdt"
)

// Common test cases that work on all architectures
func TestParseUSDTArgSpec_Common(t *testing.T) {
	negConst := int64(-9)

	tests := []struct {
		name        string
		argStr      string
		expectError bool
		expected    *usdt.ArgSpec
	}{
		{
			name:        "constant value",
			argStr:      "-4@$5",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      5,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   true,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "negative constant",
			argStr:      "-4@$-9",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      uint64(negConst),
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   true,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "large positive constant",
			argStr:      "8@$1000000",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      1000000,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "unsigned constant with max int32 value",
			argStr:      "4@$2147483647",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      2147483647,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "floating-point constant",
			argStr:      "4f@$100",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      100,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
				Arg_is_float: true,
			},
		},
		{
			name:        "bare constant without dollar sign",
			argStr:      "-4@100",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      100,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   true,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "bare constant zero",
			argStr:      "4@0",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgConst,
				Reg_id:       usdt.RegNone,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "invalid format",
			argStr:      "invalid",
			expectError: true,
		},
		{
			name:        "unknown register",
			argStr:      "8@%xyz",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArgSpec(tt.argStr)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Val_off != tt.expected.Val_off {
				t.Errorf("Val_off: got %d, want %d", result.Val_off, tt.expected.Val_off)
			}
			if result.Arg_type != tt.expected.Arg_type {
				t.Errorf("Arg_type: got %d, want %d", result.Arg_type, tt.expected.Arg_type)
			}
			if result.Reg_id != tt.expected.Reg_id {
				t.Errorf("Reg_id: got %d, want %d", result.Reg_id, tt.expected.Reg_id)
			}
			if result.Arg_signed != tt.expected.Arg_signed {
				t.Errorf("Arg_signed: got %v, want %v", result.Arg_signed, tt.expected.Arg_signed)
			}
			if result.Arg_bitshift != tt.expected.Arg_bitshift {
				t.Errorf("Arg_bitshift: got %d, want %d",
					result.Arg_bitshift, tt.expected.Arg_bitshift)
			}
			if result.Arg_is_float != tt.expected.Arg_is_float {
				t.Errorf("Arg_is_float: got %v, want %v",
					result.Arg_is_float, tt.expected.Arg_is_float)
			}
		})
	}
}

// AMD64-specific test cases
func TestParseUSDTArgSpec_AMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Skipping AMD64-specific tests on non-AMD64 platform")
	}

	negOffset := int64(-1204)
	negOffset16 := int64(-16)

	tests := []struct {
		name        string
		argStr      string
		expectError bool
		expected    *usdt.ArgSpec
	}{
		{
			name:        "register value",
			argStr:      "8@%rax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "signed register value",
			argStr:      "-4@%edi",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRdi,
				Arg_signed:   true,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "memory dereference with offset",
			argStr:      "-4@-1204(%rbp)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      uint64(negOffset),
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegRbp,
				Arg_signed:   true,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "memory dereference without offset",
			argStr:      "8@(%rsp)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegRsp,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "memory dereference with positive offset",
			argStr:      "4@100(%rbp)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      100,
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegRbp,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "memory dereference with explicit zero offset",
			argStr:      "4@0(%rbp)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegRbp,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "1 byte argument",
			argStr:      "1@%al",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   false,
				Arg_bitshift: 56, // 64 - 1*8 = 56
			},
		},
		{
			name:        "2 byte argument",
			argStr:      "2@%ax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   false,
				Arg_bitshift: 48, // 64 - 2*8 = 48
			},
		},
		{
			name:        "signed 1 byte argument",
			argStr:      "-1@%al",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   true,
				Arg_bitshift: 56, // 64 - 1*8 = 56
			},
		},
		{
			name:        "signed 2 byte argument",
			argStr:      "-2@%ax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   true,
				Arg_bitshift: 48, // 64 - 2*8 = 48
			},
		},
		{
			name:        "signed 8 byte argument",
			argStr:      "-8@%rax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   true,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "r8 register",
			argStr:      "8@%r8",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegR8,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "r15 register with 4 byte size",
			argStr:      "4@%r15d",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegR15,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "r12 in memory dereference",
			argStr:      "8@-16(%r12)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      uint64(negOffset16),
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegR12,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "floating-point register",
			argStr:      "-8f@%rax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   true,
				Arg_bitshift: 0, // 64 - 8*8 = 0
				Arg_is_float: true,
			},
		},
		{
			name:        "floating-point 4 byte register",
			argStr:      "4f@%eax",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegRax,
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
				Arg_is_float: true,
			},
		},
		{
			name:        "floating-point memory dereference",
			argStr:      "-8f@-16(%rbp)",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      uint64(negOffset16),
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegRbp,
				Arg_signed:   true,
				Arg_bitshift: 0, // 64 - 8*8 = 0
				Arg_is_float: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArgSpec(tt.argStr)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Val_off != tt.expected.Val_off {
				t.Errorf("Val_off: got %d, want %d", result.Val_off, tt.expected.Val_off)
			}
			if result.Arg_type != tt.expected.Arg_type {
				t.Errorf("Arg_type: got %d, want %d", result.Arg_type, tt.expected.Arg_type)
			}
			if result.Reg_id != tt.expected.Reg_id {
				t.Errorf("Reg_id: got %d, want %d", result.Reg_id, tt.expected.Reg_id)
			}
			if result.Arg_signed != tt.expected.Arg_signed {
				t.Errorf("Arg_signed: got %v, want %v", result.Arg_signed, tt.expected.Arg_signed)
			}
			if result.Arg_bitshift != tt.expected.Arg_bitshift {
				t.Errorf("Arg_bitshift: got %d, want %d",
					result.Arg_bitshift, tt.expected.Arg_bitshift)
			}
			if result.Arg_is_float != tt.expected.Arg_is_float {
				t.Errorf("Arg_is_float: got %v, want %v",
					result.Arg_is_float, tt.expected.Arg_is_float)
			}
		})
	}
}

// ARM64-specific test cases
func TestParseUSDTArgSpec_ARM64(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("Skipping ARM64-specific tests on non-ARM64 platform")
	}

	negOffset8 := int64(-8)

	tests := []struct {
		name        string
		argStr      string
		expectError bool
		expected    *usdt.ArgSpec
	}{
		{
			name:        "ARM64 bracket syntax with positive offset",
			argStr:      "4@[sp, 60]",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      60,
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegSP, // ARM64 bracket syntax uses ARM64 registers
				Arg_signed:   false,
				Arg_bitshift: 32, // 64 - 4*8 = 32
			},
		},
		{
			name:        "ARM64 bracket syntax with negative offset",
			argStr:      "8@[x0, -8]",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      uint64(negOffset8),
				Arg_type:     usdt.ArgRegDeref,
				Reg_id:       usdt.RegX0,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
		{
			name:        "ARM64 register without percent sign",
			argStr:      "8@x1",
			expectError: false,
			expected: &usdt.ArgSpec{
				Val_off:      0,
				Arg_type:     usdt.ArgReg,
				Reg_id:       usdt.RegX1,
				Arg_signed:   false,
				Arg_bitshift: 0, // 64 - 8*8 = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArgSpec(tt.argStr)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Val_off != tt.expected.Val_off {
				t.Errorf("Val_off: got %d, want %d", result.Val_off, tt.expected.Val_off)
			}
			if result.Arg_type != tt.expected.Arg_type {
				t.Errorf("Arg_type: got %d, want %d", result.Arg_type, tt.expected.Arg_type)
			}
			if result.Reg_id != tt.expected.Reg_id {
				t.Errorf("Reg_id: got %d, want %d", result.Reg_id, tt.expected.Reg_id)
			}
			if result.Arg_signed != tt.expected.Arg_signed {
				t.Errorf("Arg_signed: got %v, want %v", result.Arg_signed, tt.expected.Arg_signed)
			}
			if result.Arg_bitshift != tt.expected.Arg_bitshift {
				t.Errorf("Arg_bitshift: got %d, want %d",
					result.Arg_bitshift, tt.expected.Arg_bitshift)
			}
			if result.Arg_is_float != tt.expected.Arg_is_float {
				t.Errorf("Arg_is_float: got %v, want %v",
					result.Arg_is_float, tt.expected.Arg_is_float)
			}
		})
	}
}

// Common tests for ParseUSDTArguments
func TestParseUSDTArguments_Common(t *testing.T) {
	tests := []struct {
		name        string
		argString   string
		expectError bool
		expectedCnt int16
	}{
		{
			name:        "empty string",
			argString:   "",
			expectError: false,
			expectedCnt: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArguments(tt.argString)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Arg_cnt != tt.expectedCnt {
				t.Errorf("Arg_cnt: got %d, want %d", result.Arg_cnt, tt.expectedCnt)
			}
		})
	}
}

// AMD64-specific tests for ParseUSDTArguments
func TestParseUSDTArguments_AMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Skipping AMD64-specific tests on non-AMD64 platform")
	}

	tests := []struct {
		name        string
		argString   string
		expectError bool
		expectedCnt int16
	}{
		{
			name:        "single argument",
			argString:   "8@%rax",
			expectError: false,
			expectedCnt: 1,
		},
		{
			name:        "multiple arguments",
			argString:   "-4@%esi -4@-24(%rbp) -4@%ecx",
			expectError: false,
			expectedCnt: 3,
		},
		{
			name:        "complex arguments",
			argString:   "8@%rdi -4@$5 8@(%rsp) -4@-1204(%rbp)",
			expectError: false,
			expectedCnt: 4,
		},
		{
			name: "too many arguments",
			argString: "8@%rax 8@%rbx 8@%rcx 8@%rdx 8@%rsi 8@%rdi " +
				"8@%rbp 8@%rsp 8@%r8 8@%r9 8@%r10 8@%r11 8@%r12",
			expectError: true, // More than 12 args
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArguments(tt.argString)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Arg_cnt != tt.expectedCnt {
				t.Errorf("Arg_cnt: got %d, want %d", result.Arg_cnt, tt.expectedCnt)
			}
		})
	}
}

// ARM64-specific tests for ParseUSDTArguments
func TestParseUSDTArguments_ARM64(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("Skipping ARM64-specific tests on non-ARM64 platform")
	}

	tests := []struct {
		name        string
		argString   string
		expectError bool
		expectedCnt int16
	}{
		{
			name:        "ARM64 brackets with spaces",
			argString:   "4@[sp, 44] 4@[sp, 16] 8@[sp, 48]",
			expectError: false,
			expectedCnt: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUSDTArguments(tt.argString)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Arg_cnt != tt.expectedCnt {
				t.Errorf("Arg_cnt: got %d, want %d", result.Arg_cnt, tt.expectedCnt)
			}
		})
	}
}

func TestUSDTSpecToBytes(t *testing.T) {
	negOffset := int64(-1204)

	spec := &usdt.Spec{
		Arg_cnt: 2,
	}
	spec.Args[0] = usdt.ArgSpec{
		Val_off:      0,
		Arg_type:     usdt.ArgReg,
		Reg_id:       usdt.RegRax,
		Arg_signed:   false,
		Arg_bitshift: 0,
	}
	spec.Args[1] = usdt.ArgSpec{
		Val_off:      uint64(negOffset),
		Arg_type:     usdt.ArgRegDeref,
		Reg_id:       usdt.RegRax,
		Arg_signed:   true,
		Arg_bitshift: 32,
	}

	bytes := USDTSpecToBytes(spec)
	if len(bytes) == 0 {
		t.Error("ToBytes returned empty byte slice")
	}

	// The size should match the C struct size
	// struct bpf_usdt_spec has:
	// - 12 * bpf_usdt_arg_spec (each ~22 bytes with packing)
	// - u64 usdt_cookie (8 bytes)
	// - s16 arg_cnt (2 bytes)
	// - u8 _pad[6] (6 bytes)
	// Total should be reasonable size
	if len(bytes) < 200 {
		t.Errorf("ToBytes returned unexpectedly small byte slice: %d bytes", len(bytes))
	}
}
