// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/support/usdt"
)

// x86_64 register name to ID mapping
// Maps all register name variants (64-bit, 32-bit, 16-bit, 8-bit) to register IDs
var x86_64RegNameToID = map[string]usdt.Register{
	"rax": usdt.RegRax, "eax": usdt.RegRax, "ax": usdt.RegRax, "al": usdt.RegRax,
	"rbx": usdt.RegRbx, "ebx": usdt.RegRbx, "bx": usdt.RegRbx, "bl": usdt.RegRbx,
	"rcx": usdt.RegRcx, "ecx": usdt.RegRcx, "cx": usdt.RegRcx, "cl": usdt.RegRcx,
	"rdx": usdt.RegRdx, "edx": usdt.RegRdx, "dx": usdt.RegRdx, "dl": usdt.RegRdx,
	"rsi": usdt.RegRsi, "esi": usdt.RegRsi, "si": usdt.RegRsi, "sil": usdt.RegRsi,
	"rdi": usdt.RegRdi, "edi": usdt.RegRdi, "di": usdt.RegRdi, "dil": usdt.RegRdi,
	"rbp": usdt.RegRbp, "ebp": usdt.RegRbp, "bp": usdt.RegRbp, "bpl": usdt.RegRbp,
	"rsp": usdt.RegRsp, "esp": usdt.RegRsp, "sp": usdt.RegRsp, "spl": usdt.RegRsp,
	"r8": usdt.RegR8, "r8d": usdt.RegR8, "r8w": usdt.RegR8, "r8b": usdt.RegR8,
	"r9": usdt.RegR9, "r9d": usdt.RegR9, "r9w": usdt.RegR9, "r9b": usdt.RegR9,
	"r10": usdt.RegR10, "r10d": usdt.RegR10, "r10w": usdt.RegR10, "r10b": usdt.RegR10,
	"r11": usdt.RegR11, "r11d": usdt.RegR11, "r11w": usdt.RegR11, "r11b": usdt.RegR11,
	"r12": usdt.RegR12, "r12d": usdt.RegR12, "r12w": usdt.RegR12, "r12b": usdt.RegR12,
	"r13": usdt.RegR13, "r13d": usdt.RegR13, "r13w": usdt.RegR13, "r13b": usdt.RegR13,
	"r14": usdt.RegR14, "r14d": usdt.RegR14, "r14w": usdt.RegR14, "r14b": usdt.RegR14,
	"r15": usdt.RegR15, "r15d": usdt.RegR15, "r15w": usdt.RegR15, "r15b": usdt.RegR15,
	"rip": usdt.RegRip, "eip": usdt.RegRip, "ip": usdt.RegRip,
}

// ARM64 register name to ID mapping
// Maps all register name variants (64-bit and 32-bit) to register IDs
var arm64RegNameToID = map[string]usdt.Register{
	"x0": usdt.RegX0, "w0": usdt.RegX0,
	"x1": usdt.RegX1, "w1": usdt.RegX1,
	"x2": usdt.RegX2, "w2": usdt.RegX2,
	"x3": usdt.RegX3, "w3": usdt.RegX3,
	"x4": usdt.RegX4, "w4": usdt.RegX4,
	"x5": usdt.RegX5, "w5": usdt.RegX5,
	"x6": usdt.RegX6, "w6": usdt.RegX6,
	"x7": usdt.RegX7, "w7": usdt.RegX7,
	"x8": usdt.RegX8, "w8": usdt.RegX8,
	"x9": usdt.RegX9, "w9": usdt.RegX9,
	"x10": usdt.RegX10, "w10": usdt.RegX10,
	"x11": usdt.RegX11, "w11": usdt.RegX11,
	"x12": usdt.RegX12, "w12": usdt.RegX12,
	"x13": usdt.RegX13, "w13": usdt.RegX13,
	"x14": usdt.RegX14, "w14": usdt.RegX14,
	"x15": usdt.RegX15, "w15": usdt.RegX15,
	"x16": usdt.RegX16, "w16": usdt.RegX16,
	"x17": usdt.RegX17, "w17": usdt.RegX17,
	"x18": usdt.RegX18, "w18": usdt.RegX18,
	"x19": usdt.RegX19, "w19": usdt.RegX19,
	"x20": usdt.RegX20, "w20": usdt.RegX20,
	"x21": usdt.RegX21, "w21": usdt.RegX21,
	"x22": usdt.RegX22, "w22": usdt.RegX22,
	"x23": usdt.RegX23, "w23": usdt.RegX23,
	"x24": usdt.RegX24, "w24": usdt.RegX24,
	"x25": usdt.RegX25, "w25": usdt.RegX25,
	"x26": usdt.RegX26, "w26": usdt.RegX26,
	"x27": usdt.RegX27, "w27": usdt.RegX27,
	"x28": usdt.RegX28, "w28": usdt.RegX28,
	"x29": usdt.RegX29, "w29": usdt.RegX29, "fp": usdt.RegX29,
	"x30": usdt.RegX30, "w30": usdt.RegX30, "lr": usdt.RegX30,
	"sp": usdt.RegSP, "wsp": usdt.RegSP,
	"pc": usdt.RegPC,
}

// lookupRegister looks up a register ID by name based on the runtime architecture
func lookupRegister(regName string) (usdt.Register, bool) {
	switch runtime.GOARCH {
	case "amd64":
		if regID, ok := x86_64RegNameToID[regName]; ok {
			return regID, true
		}
	case "arm64":
		if regID, ok := arm64RegNameToID[regName]; ok {
			return regID, true
		}
	}
	return 0, false
}

// Regex patterns for parsing USDT argument specifications
// USDT argument format: SIZE@LOCATION where:
//   SIZE: byte size (negative for signed)
//   LOCATION: register (%rax), memory offset(%reg) or [reg, offset], or constant ($123 or 123)
var (
	// Memory dereference with offset - x86_64 syntax: -4@-1204(%rbp) or -4f@-1204(%rbp)
	regexRegDerefWithOffset = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*(-?\d+)\s*\(\s*%([a-z0-9]+)\s*\)\s*$`)
	// Memory dereference with offset - ARM64 syntax: -4@[sp, 60] or 4@[x0, -8]
	regexRegDerefWithOffsetARM = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*\[\s*([a-z0-9]+)\s*,\s*(-?\d+)\s*\]\s*$`)
	// Memory dereference without offset: 8@(%rsp) or 8f@(%rsp)
	regexRegDerefNoOffset = regexp.MustCompile(
		`^\s*(-?\d+)(f?)\s*@\s*\(\s*%([a-z0-9]+)\s*\)\s*$`)
	// Immediate constant with dollar sign: -4@$5 or -4@$-9 or -4f@$5
	regexConst = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*\$(-?\d+)\s*$`)
	// Bare constant (no dollar sign): -4@100 or 4@0 or -4f@100
	// Note: Must be checked BEFORE regexReg since regexReg would also match bare numbers
	regexBareConst = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*(-?\d+)\s*$`)
	// Register value: 8@%rax or -4@%edi or -4f@%edi or 8@x0 (ARM64)
	regexReg = regexp.MustCompile(`^\s*(-?\d+)(f?)\s*@\s*%?([a-z0-9]+)\s*$`)
)

// https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
// ParseUSDTArgSpec parses a single USDT argument specification string
// Examples: "-4@-1204(%rbp)", "8@%rax", "-4@$5", "-4@100", "8@(%rsp)", "-8f@%xmm0"
func ParseUSDTArgSpec(argStr string) (*usdt.ArgSpec, error) {
	argStr = strings.TrimSpace(argStr)
	if argStr == "" {
		return nil, errors.New("empty argument string")
	}

	spec := &usdt.ArgSpec{}

	// Try memory dereference with offset first (x86_64 syntax)
	if matches := regexRegDerefWithOffset.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		offset, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory offset: %w", err)
		}
		regName := matches[4]

		spec.Arg_type = usdt.ArgRegDeref
		spec.Val_off = uint64(offset)
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try memory dereference with offset (ARM64 bracket syntax)
	if matches := regexRegDerefWithOffsetARM.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]
		offset, err := strconv.ParseInt(matches[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory offset: %w", err)
		}

		spec.Arg_type = usdt.ArgRegDeref
		spec.Val_off = uint64(offset)
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try memory dereference without offset
	if matches := regexRegDerefNoOffset.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]

		spec.Arg_type = usdt.ArgRegDeref
		spec.Val_off = 0
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try immediate constant with dollar sign
	if matches := regexConst.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		constVal, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid constant value: %w", err)
		}

		spec.Arg_type = usdt.ArgConst
		spec.Val_off = uint64(constVal)
		spec.Reg_id = usdt.RegNone
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try bare constant (no dollar sign) - must be checked before regexReg
	if matches := regexBareConst.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		constVal, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid constant value: %w", err)
		}

		spec.Arg_type = usdt.ArgConst
		spec.Val_off = uint64(constVal)
		spec.Reg_id = usdt.RegNone
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	// Try register value
	if matches := regexReg.FindStringSubmatch(argStr); matches != nil {
		argSz, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid arg size: %w", err)
		}
		isFloat := matches[2] == "f"
		regName := matches[3]

		spec.Arg_type = usdt.ArgReg
		spec.Val_off = 0
		regID, ok := lookupRegister(regName)
		if !ok {
			return nil, fmt.Errorf("unknown register: %s", regName)
		}
		spec.Reg_id = regID
		spec.Arg_signed = argSz < 0
		spec.Arg_is_float = isFloat
		if argSz < 0 {
			argSz = -argSz
		}
		spec.Arg_bitshift = int8(64 - argSz*8)
		return spec, nil
	}

	return nil, fmt.Errorf("unrecognized argument format: %s", argStr)
}

// splitUSDTArgs splits a USDT argument string into individual argument specifications.
// Unlike strings.Fields, this preserves spaces inside brackets for ARM64 syntax like "4@[sp, 44]".
func splitUSDTArgs(argString string) []string {
	var args []string
	var current strings.Builder
	inBrackets := false

	for _, ch := range argString {
		switch ch {
		case '[':
			inBrackets = true
			current.WriteRune(ch)
		case ']':
			inBrackets = false
			current.WriteRune(ch)
		case ' ', '\t', '\n', '\r':
			if inBrackets {
				// Preserve spaces inside brackets
				current.WriteRune(ch)
			} else if current.Len() > 0 {
				// End of argument outside brackets
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}

	// Add final argument if any
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// ParseUSDTArguments parses a USDT argument specification string into a usdt.Spec.
// The argument string is space-separated (e.g., "-4@%esi -4@-24(%rbp) -4@%ecx").
// For ARM64, brackets can contain spaces (e.g., "4@[sp, 44] 8@[x0, -8]").
func ParseUSDTArguments(argString string) (*usdt.Spec, error) {
	argString = strings.TrimSpace(argString)
	if argString == "" {
		// No arguments is valid
		return &usdt.Spec{Arg_cnt: 0}, nil
	}

	// Split by whitespace, but preserve spaces inside brackets
	argStrs := splitUSDTArgs(argString)
	if len(argStrs) > 12 {
		return nil, fmt.Errorf("too many arguments: %d (max 12)", len(argStrs))
	}

	spec := &usdt.Spec{
		Arg_cnt: int16(len(argStrs)),
	}

	for i, argStr := range argStrs {
		argSpec, err := ParseUSDTArgSpec(argStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse argument %d (%s): %w", i, argStr, err)
		}
		spec.Args[i] = *argSpec
	}

	return spec, nil
}

// USDTSpecToBytes converts usdt.Spec to byte slice for BPF map updates
func USDTSpecToBytes(s *usdt.Spec) []byte {
	// We need to convert to a byte slice that matches the C struct layout
	// This is architecture-specific and assumes little-endian
	size := int(unsafe.Sizeof(*s))
	return unsafe.Slice((*byte)(unsafe.Pointer(s)), size)
}
