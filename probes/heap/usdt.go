// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

const heapAllocArgumentCount = 3

func parseAllocSpec(point usdt.AttachmentPoint) (support.USDTSpec, error) {
	parsed, err := usdt.ParseArguments(point.Arguments, point.Machine)
	if err != nil {
		return support.USDTSpec{}, err
	}
	if parsed.ArgumentCount != heapAllocArgumentCount {
		return support.USDTSpec{}, fmt.Errorf("alloc probe has %d arguments, want %d",
			parsed.ArgumentCount, heapAllocArgumentCount)
	}

	var spec support.USDTSpec
	for i := range heapAllocArgumentCount {
		arg := parsed.Arguments[i]
		if arg.Size() != 8 || arg.IsSigned() || arg.IsFloat() {
			return support.USDTSpec{}, fmt.Errorf(
				"alloc argument %d must be an unsigned 8-byte integer", i)
		}
		var registerOffset uint16
		switch arg.Kind {
		case usdt.ArgumentConstant:
		case usdt.ArgumentRegister, usdt.ArgumentRegisterDereference:
			registerOffset, err = arg.Register.PTRegsOffset(point.Machine)
			if err != nil {
				return support.USDTSpec{}, fmt.Errorf("convert alloc argument %d: %w", i, err)
			}
		default:
			return support.USDTSpec{}, fmt.Errorf(
				"convert alloc argument %d: unsupported argument kind %d", i, arg.Kind)
		}
		spec.Arguments[i] = support.USDTArgumentSpec{
			Value_offset:    arg.ValueOffset,
			Register_offset: registerOffset,
			Kind:            uint8(arg.Kind),
		}
	}
	spec.Count = parsed.ArgumentCount
	return spec, nil
}
