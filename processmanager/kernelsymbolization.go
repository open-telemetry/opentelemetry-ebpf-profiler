// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"unique"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func symbolizeBPFFrame(name string, offset uint) unique.Handle[libpf.Frame] {
	return unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: libpf.AddressOrLineno(offset),
		FunctionName:    libpf.Intern(name),
	})
}

func symbolizeKernelFrame(
	address libpf.Address, resolution kallsyms.AddressResolution,
) (unique.Handle[libpf.Frame], bool) {
	if resolution.Source == kallsyms.SymbolSourceBPF {
		return symbolizeBPFFrame(resolution.BPFName, resolution.BPFOffset), true
	}

	frame := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: libpf.AddressOrLineno(address - 1),
	}
	cacheable := false

	if kmod := resolution.Module; kmod != nil {
		frame.Mapping = kmod.Mapping()
		cacheable = frame.Mapping.Valid()
		frame.AddressOrLineno -= libpf.AddressOrLineno(kmod.Start())
		if funcName, _, err := kmod.LookupSymbolByAddress(address); err == nil {
			frame.FunctionName = libpf.Intern(funcName)
		}
	}

	return unique.Make(frame), cacheable
}
