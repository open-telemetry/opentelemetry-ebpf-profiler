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
		spec.Arguments[i] = support.USDTArgumentSpec{
			Value_offset: arg.ValueOffset,
			Kind:         uint32(arg.Kind),
			Reg:          uint8(arg.Register),
			Is_signed:    arg.Signed,
			Bit_shift:    arg.BitShift,
			Is_float:     arg.Float,
		}
	}
	spec.Count = parsed.ArgumentCount
	return spec, nil
}
