// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rtld // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld"

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// data holds the Uprobe link to keep it in memory
type data struct {
	path    string
	address uint64
	lc      interpreter.LinkCloser
}

// instance represents a per-PID instance of the dlopen interpreter
type instance struct {
	interpreter.InstanceStubs
}

// Loader detects if the ELF file contains the dlopen symbol in its dynamic symbol table
func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	fileName := info.FileName()

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Look for the dlopen symbol in the dynamic symbol table
	sym, err := ef.LookupSymbol("dlopen")
	if err != nil || sym == nil {
		return nil, nil
	}

	// Skip if the symbol address is invalid (0)
	if sym.Address == 0 {
		return nil, nil
	}

	log.Debugf("Found dlopen symbol in %s at 0x%x", fileName, sym.Address)

	return &data{
		path:    fileName,
		address: uint64(sym.Address),
	}, nil
}

// Attach attaches the uprobe to the dlopen function
func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	var lc interpreter.LinkCloser
	if d.lc == nil {
		// Attach uprobe to dlopen using the address stored during Loader
		var err error
		lc, err = ebpf.AttachUprobe(pid, d.path, d.address, "uprobe_dlopen")
		if err != nil {
			return nil, fmt.Errorf("failed to attach uprobe to dlopen: %w", err)
		}
		d.lc = lc
	}

	log.Debugf("[dlopen] Attached uprobe to dlopen for PID %d on %s at 0x%x",
		pid, d.path, d.address)

	return &instance{}, nil
}

// Unload cleans up the uprobe link
func (d *data) Unload(_ interpreter.EbpfHandler) {
	if d.lc != nil {
		if err := d.lc.Unload(); err != nil {
			log.Errorf("[dlopen] Failed to unload uprobe link: %v", err)
		}
	}
	log.Debugf("[dlopen] Unloaded uprobe for %s", d.path)
}
