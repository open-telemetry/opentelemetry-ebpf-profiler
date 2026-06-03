// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package rtld attaches a uprobe to libc's dlopen() to drive a userspace
// re-scan of /proc/<pid>/maps whenever a profiled process loads a new shared
// object. Without this, runtime-loaded interpreter shared libraries are only
// picked up by the next periodic mapping refresh.
package rtld // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// data holds the uprobe link in memory so that the attachment outlives the
// Loader/Attach call. It is keyed per executable (FileID).
type data struct {
	path    string
	address uint64
	lc      interpreter.LinkCloser
}

// instance is the per-PID state for the rtld loader. The dlopen uprobe needs
// no per-PID introspection so we only embed InstanceStubs and provide a
// no-op Detach (the uprobe is keyed per executable, not per PID, and is
// released via Data.Unload).
type instance struct {
	interpreter.InstanceStubs
}

// Detach is a no-op: the dlopen uprobe is owned by the per-DSO data, not by
// any individual PID.
func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

// Loader detects whether the given ELF exports a dlopen symbol in its dynamic
// symbol table. If yes, it returns Data carrying the address so Attach can
// later install a uprobe at that offset.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	sym, err := ef.LookupSymbol("dlopen")
	if err != nil || sym == nil || sym.Address == 0 {
		return nil, nil
	}

	log.Debugf("Found dlopen symbol in %s at 0x%x", info.FileName(), sym.Address)
	return &data{
		path:    info.FileName(),
		address: uint64(sym.Address),
	}, nil
}

// Attach installs the uprobe on the dlopen symbol of this DSO for the given
// PID. The uprobe is shared across PIDs that map the same ELF; we only attach
// once per Data.
func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if d.lc == nil {
		lc, err := ebpf.AttachUprobe(pid, d.path, d.address, "uprobe_dlopen")
		if err != nil {
			return nil, fmt.Errorf("failed to attach uprobe to dlopen: %w", err)
		}
		d.lc = lc
	}
	return &instance{}, nil
}

// Unload detaches the uprobe.
func (d *data) Unload(_ interpreter.EbpfHandler) {
	if d.lc != nil {
		if err := d.lc.Unload(); err != nil {
			log.Errorf("[dlopen] Failed to unload uprobe link: %v", err)
		}
	}
}
