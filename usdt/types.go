// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package usdt discovers User Statically-Defined Tracepoint probes in ELF
// mappings.
package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import "debug/elf"

// AttachmentPoint describes a discovered USDT location. Location and
// SemaphoreOffset are ELF file offsets suitable for uprobe attachment.
type AttachmentPoint struct {
	Provider string
	Name     string

	// Location is the ELF file offset used to attach the uprobe.
	Location uint64
	// ELFAddress is the adjusted virtual address from the SDT descriptor.
	ELFAddress uint64
	// SemaphoreOffset is the ELF file offset of the optional SDT semaphore.
	SemaphoreOffset uint64

	// Arguments is the raw SDT argument-location descriptor.
	Arguments string
	// Machine identifies the ELF architecture used to interpret Arguments.
	Machine elf.Machine
}
