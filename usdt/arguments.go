// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"debug/elf"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxArguments is the maximum number of arguments carried by a USDT Spec.
const MaxArguments = 12

// ArgumentKind describes how an SDT argument value is obtained.
type ArgumentKind uint32

const (
	ArgumentConstant ArgumentKind = iota
	ArgumentRegister
	ArgumentRegisterDereference
)

// Register identifies an architecture register referenced by an SDT argument.
type Register uint8

const (
	RegisterNone Register = iota

	// amd64 registers.
	RegisterRAX
	RegisterRBX
	RegisterRCX
	RegisterRDX
	RegisterRSI
	RegisterRDI
	RegisterRBP
	RegisterRSP
	RegisterR8
	RegisterR9
	RegisterR10
	RegisterR11
	RegisterR12
	RegisterR13
	RegisterR14
	RegisterR15
	RegisterRIP
)

const (
	// arm64 registers occupy a separate range from the amd64 identifiers.
	// The numbered registers are contiguous and resolved relative to X0.
	RegisterX0  Register = 32
	RegisterX30 Register = RegisterX0 + 30
	RegisterSP  Register = RegisterX30 + 1
	RegisterPC  Register = RegisterSP + 1
)

// ArgumentSpec describes one parsed SDT argument. ValueOffset holds either a
// constant value or a signed register displacement.
type ArgumentSpec struct {
	ValueOffset uint64
	Kind        ArgumentKind
	Register    Register
	Signed      uint8
	BitShift    int8
	Float       uint8
}

// IsSigned reports whether the argument should be sign-extended.
func (s ArgumentSpec) IsSigned() bool { return s.Signed != 0 }

// IsFloat reports whether the argument contains floating-point bits.
func (s ArgumentSpec) IsFloat() bool { return s.Float != 0 }

// Size returns the argument width in bytes.
func (s ArgumentSpec) Size() uint8 { return uint8((64 - int(s.BitShift)) / 8) }

// Spec describes the parsed arguments at one USDT attachment point.
type Spec struct {
	Arguments     [MaxArguments]ArgumentSpec
	ArgumentCount uint8
}

// ParseArguments parses the space-separated argument-location string stored in
// a SystemTap SDT note. Each argument has the form <size>[f]@<location>, where
// a negative size denotes a signed value and f denotes floating-point bits.
// Parsing preserves this metadata, but consumers must validate the subset they
// support. The current heap consumer accepts unsigned, non-floating 64-bit values.
//
// See [SystemTap userspace probe implementation] for the SDT note ABI.
//
// [SystemTap userspace probe implementation]: https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
func ParseArguments(raw string, machine elf.Machine) (Spec, error) {
	var spec Spec
	parts, err := splitArguments(raw)
	if err != nil {
		return spec, err
	}
	if len(parts) > MaxArguments {
		return spec, fmt.Errorf("too many USDT arguments: %d (max %d)", len(parts), MaxArguments)
	}

	for i, part := range parts {
		arg, err := parseArgument(part, machine)
		if err != nil {
			return Spec{}, fmt.Errorf("parse USDT argument %d %q: %w", i, part, err)
		}
		spec.Arguments[i] = arg
	}
	spec.ArgumentCount = uint8(len(parts))
	return spec, nil
}

// splitArguments separates SDT arguments on top-level whitespace. Whitespace
// inside an architecture-specific memory operand, such as [sp, 40], remains
// part of that argument.
func splitArguments(raw string) ([]string, error) {
	var parts []string
	var current strings.Builder
	depth := 0

	// SDT arguments are not quoted, so bracket and parenthesis depth
	// distinguishes separators from whitespace inside memory operands.
	for _, r := range strings.TrimSpace(raw) {
		switch r {
		case '[', '(':
			depth++
			current.WriteRune(r)
		case ']', ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced USDT argument delimiters")
			}
			current.WriteRune(r)
		case ' ', '\t', '\n', '\r':
			if depth != 0 {
				current.WriteRune(r)
			} else if current.Len() != 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced USDT argument delimiters")
	}
	if current.Len() != 0 {
		parts = append(parts, current.String())
	}
	return parts, nil
}

func parseArgument(raw string, machine elf.Machine) (ArgumentSpec, error) {
	size, location, ok := strings.Cut(raw, "@")
	if !ok {
		return ArgumentSpec{}, errors.New("missing argument location separator")
	}

	spec, err := sizedSpec(size)
	if err != nil {
		return ArgumentSpec{}, err
	}
	return parseLocation(spec, location, machine)
}

func parseLocation(spec ArgumentSpec, location string, machine elf.Machine) (ArgumentSpec, error) {
	if value, ok := constantLocation(location); ok {
		return constantSpec(spec, value)
	}

	switch machine {
	case elf.EM_X86_64:
		return parseX86Location(spec, location)
	case elf.EM_AARCH64:
		return parseARM64Location(spec, location)
	default:
		return ArgumentSpec{}, fmt.Errorf("unsupported machine %s", machine)
	}
}

func parseX86Location(spec ArgumentSpec, location string) (ArgumentSpec, error) {
	if strings.HasSuffix(location, ")") {
		open := strings.IndexByte(location, '(')
		if open == -1 {
			return ArgumentSpec{}, errors.New("invalid amd64 register dereference")
		}

		displacement := location[:open]
		if displacement == "" {
			displacement = "0"
		}
		register := location[open+1 : len(location)-1]
		if !strings.HasPrefix(register, "%") {
			return ArgumentSpec{}, errors.New("amd64 dereference register must start with %")
		}
		return dereferenceSpec(spec, displacement, strings.TrimPrefix(register, "%"), elf.EM_X86_64)
	}

	return registerSpec(spec, strings.TrimPrefix(location, "%"), elf.EM_X86_64)
}

func parseARM64Location(spec ArgumentSpec, location string) (ArgumentSpec, error) {
	if strings.HasPrefix(location, "[") {
		if !strings.HasSuffix(location, "]") {
			return ArgumentSpec{}, errors.New("invalid arm64 register dereference")
		}

		parts := strings.Split(location[1:len(location)-1], ",")
		if len(parts) > 2 {
			return ArgumentSpec{}, errors.New("invalid arm64 register dereference")
		}
		register := strings.TrimSpace(parts[0])
		displacement := "0"
		if len(parts) == 2 {
			displacement = strings.TrimSpace(parts[1])
		}
		return dereferenceSpec(spec, displacement, register, elf.EM_AARCH64)
	}

	return registerSpec(spec, strings.TrimPrefix(location, "%"), elf.EM_AARCH64)
}

func registerSpec(spec ArgumentSpec, name string, machine elf.Machine) (ArgumentSpec, error) {
	reg, ok := lookupRegister(name, machine)
	if !ok {
		return ArgumentSpec{}, fmt.Errorf("unknown register %q for %s", name, machine)
	}
	spec.Kind = ArgumentRegister
	spec.Register = reg
	return spec, nil
}

func dereferenceSpec(spec ArgumentSpec, offset, register string,
	machine elf.Machine,
) (ArgumentSpec, error) {
	if !isDecimal(offset) {
		return ArgumentSpec{}, fmt.Errorf("invalid register displacement %q", offset)
	}
	displacement, err := strconv.ParseInt(offset, 10, 64)
	if err != nil {
		return ArgumentSpec{}, fmt.Errorf("invalid register displacement: %w", err)
	}
	reg, ok := lookupRegister(register, machine)
	if !ok {
		return ArgumentSpec{}, fmt.Errorf("unknown register %q for %s", register, machine)
	}
	spec.Kind = ArgumentRegisterDereference
	spec.Register = reg
	spec.ValueOffset = uint64(displacement)
	return spec, nil
}

func constantSpec(spec ArgumentSpec, value string) (ArgumentSpec, error) {
	if !isDecimal(value) {
		return ArgumentSpec{}, fmt.Errorf("invalid constant %q", value)
	}
	constantValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return ArgumentSpec{}, fmt.Errorf("invalid constant: %w", err)
	}
	spec.Kind = ArgumentConstant
	spec.ValueOffset = uint64(constantValue)
	return spec, nil
}

func constantLocation(location string) (string, bool) {
	if value, ok := strings.CutPrefix(location, "$"); ok {
		return value, true
	}
	return location, isDecimal(location)
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '-' {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sizedSpec(raw string) (ArgumentSpec, error) {
	var isFloat uint8
	if strings.HasSuffix(strings.ToLower(raw), "f") {
		isFloat = 1
		raw = raw[:len(raw)-1]
	}
	if !isDecimal(raw) {
		return ArgumentSpec{}, fmt.Errorf("invalid argument size %q", raw)
	}
	width, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return ArgumentSpec{}, fmt.Errorf("invalid argument size: %w", err)
	}
	var signed uint8
	if width < 0 {
		signed = 1
		width = -width
	}
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return ArgumentSpec{}, fmt.Errorf("unsupported argument size %d", width)
	}
	return ArgumentSpec{
		Signed:   signed,
		BitShift: int8(64 - width*8),
		Float:    isFloat,
	}, nil
}

// lookupRegister resolves an architecture register name to the identifier used
// by the BPF decoder. Width aliases map to the same saved register because the
// argument descriptor carries the value width separately.
func lookupRegister(name string, machine elf.Machine) (Register, bool) {
	name = strings.ToLower(name)
	switch machine {
	case elf.EM_X86_64:
		reg, ok := x86Registers[name]
		return reg, ok
	case elf.EM_AARCH64:
		return lookupARM64Register(name)
	default:
		return RegisterNone, false
	}
}

func lookupARM64Register(name string) (Register, bool) {
	switch name {
	case "sp", "wsp":
		return RegisterSP, true
	case "pc":
		return RegisterPC, true
	}

	// xN and wN name the same pt_regs entry; their value width remains
	// available separately in the parsed descriptor.
	if len(name) < 2 || name[0] != 'x' && name[0] != 'w' {
		return RegisterNone, false
	}
	number, err := strconv.ParseUint(name[1:], 10, 8)
	if err != nil || number > 30 {
		return RegisterNone, false
	}
	return RegisterX0 + Register(number), true
}

// x86Registers maps each width-specific name to its containing pt_regs slot.
var x86Registers = map[string]Register{
	"rax": RegisterRAX, "eax": RegisterRAX, "ax": RegisterRAX, "al": RegisterRAX,
	"rbx": RegisterRBX, "ebx": RegisterRBX, "bx": RegisterRBX, "bl": RegisterRBX,
	"rcx": RegisterRCX, "ecx": RegisterRCX, "cx": RegisterRCX, "cl": RegisterRCX,
	"rdx": RegisterRDX, "edx": RegisterRDX, "dx": RegisterRDX, "dl": RegisterRDX,
	"rsi": RegisterRSI, "esi": RegisterRSI, "si": RegisterRSI, "sil": RegisterRSI,
	"rdi": RegisterRDI, "edi": RegisterRDI, "di": RegisterRDI, "dil": RegisterRDI,
	"rbp": RegisterRBP, "ebp": RegisterRBP, "bp": RegisterRBP, "bpl": RegisterRBP,
	"rsp": RegisterRSP, "esp": RegisterRSP, "sp": RegisterRSP, "spl": RegisterRSP,
	"r8": RegisterR8, "r8d": RegisterR8, "r8w": RegisterR8, "r8b": RegisterR8,
	"r9": RegisterR9, "r9d": RegisterR9, "r9w": RegisterR9, "r9b": RegisterR9,
	"r10": RegisterR10, "r10d": RegisterR10, "r10w": RegisterR10, "r10b": RegisterR10,
	"r11": RegisterR11, "r11d": RegisterR11, "r11w": RegisterR11, "r11b": RegisterR11,
	"r12": RegisterR12, "r12d": RegisterR12, "r12w": RegisterR12, "r12b": RegisterR12,
	"r13": RegisterR13, "r13d": RegisterR13, "r13w": RegisterR13, "r13b": RegisterR13,
	"r14": RegisterR14, "r14d": RegisterR14, "r14w": RegisterR14, "r14b": RegisterR14,
	"r15": RegisterR15, "r15d": RegisterR15, "r15w": RegisterR15, "r15b": RegisterR15,
	"rip": RegisterRIP, "eip": RegisterRIP, "ip": RegisterRIP,
}
