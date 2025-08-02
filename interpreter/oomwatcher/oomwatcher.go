// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oomwatcher // import "go.opentelemetry.io/ebpf-profiler/interpreter/oomwatcher"

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/parca-dev/oomprof/oomprof"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// oomWatcherData holds per-executable data for the OOM watcher observer.
type oomWatcherData struct {
	state *oomprof.State
}

// oomWatcherInstance holds per-process state for the OOM watcher observer.
type oomWatcherInstance struct {
	interpreter.InstanceStubs
	pid  libpf.PID
	data *oomWatcherData
}

// Loader detects Go binaries and checks for mbucket symbol to determine
// if OOM watching should be enabled.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	// Try to get the global oomprof state
	state, err := oomprof.GetState()
	if err != nil {
		// oomprof not initialized, OOM prof must be initialized early by the otel container
		// project so it can be wired up to a TraceReporter instance.
		log.Debugf("OOM watcher: oomprof not initialized, disabling OOM watching: %v", err)
		return nil, nil
	}

	file, err := info.GetELF()
	if err != nil {
		log.Debugf("OOM watcher: elf err, disabling OOM watching: %v", err)
		return nil, err
	}

	// Check if this is a Go binary
	if !file.IsGolang() {
		if strings.Contains(info.FileName(), "oomprof") {
			log.Debugf("OOM watcher: not go, disabling OOM watching: %s", info.FileName())
		}
		return nil, nil
	}

	// Read the symbol table
	symtab, err := file.ReadSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read symbols for file %s: %w", info.FileName(), err)
	}

	// Check for mbuckets symbol
	sym, err := symtab.LookupSymbol("runtime.mbuckets")
	if err != nil {
		return nil, err
	}

	if sym != nil {
		log.Debugf("OOM watcher: found mbuckets symbol (%v) in %s", sym, info.FileName())
		return &oomWatcherData{
			state: state,
		}, nil
	}
	log.Debugf("OOM watcher: no mbuckets symbol found %s", info.FileName())

	return nil, nil
}

// Attach creates an observer instance for the given process.
func (d *oomWatcherData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	instance := &oomWatcherInstance{
		pid:  pid,
		data: d,
	}

	// Only watch PIDs for Go processes with mbucket symbol
	if d.state != nil {
		log.Debugf("OOM watcher: watching PID %d", pid)
		if err := d.state.WatchPid(uint32(pid)); err != nil {
			if err == oomprof.ErrSelfWatch {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to watch PID %d: %w", pid, err)
		}
	}

	return instance, nil
}

// Detach stops watching the process.
func (i *oomWatcherInstance) Detach(_ interpreter.EbpfHandler, pid libpf.PID) error {
	log.Debugf("OOM watcher: stopping watch for PID %d", pid)
	i.data.state.UnwatchPid(uint32(pid))
	return nil
}

// Unload cleans up any resources.
func (d *oomWatcherData) Unload(_ interpreter.EbpfHandler) {
	// No global resources to clean up
}
