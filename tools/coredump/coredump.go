// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/process"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
// int unwind_traces(u64 id, int debug, u64 tp_base, void *ctx);
import "C"

// sliceBuffer creates a Go slice from C buffer
func sliceBuffer(buf unsafe.Pointer, sz C.int) []byte {
	return unsafe.Slice((*byte)(buf), int(sz))
}

// symbolizationCache collects and caches the interpreter manager's symbolization
// callbacks to be used for trace stringification.
type symbolizationCache struct {
	files map[libpf.FileID]string
}

func newSymbolizationCache() *symbolizationCache {
	return &symbolizationCache{
		files: make(map[libpf.FileID]string),
	}
}

func (c *symbolizationCache) ExecutableKnown(fileID libpf.FileID) bool {
	_, exists := c.files[fileID]
	return exists
}

func (c *symbolizationCache) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	c.files[args.FileID] = args.FileName
}

func generateErrorMap() (map[libpf.AddressOrLineno]string, error) {
	file, err := os.Open("../errors-codegen/errors.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open errors.json: %w", err)
	}

	type JSONError struct {
		ID   uint64 `json:"id"`
		Name string `json:"name"`
	}

	var errors []JSONError
	if err = json.NewDecoder(file).Decode(&errors); err != nil {
		return nil, fmt.Errorf("failed to parse errors.json: %w", err)
	}

	out := make(map[libpf.AddressOrLineno]string, len(errors))
	for _, item := range errors {
		out[libpf.AddressOrLineno(item.ID)] = item.Name
	}

	return out, nil
}

var errorMap xsync.Once[map[libpf.AddressOrLineno]string]

func (c *symbolizationCache) formatFrame(frame *libpf.Frame) (string, error) {
	if frame.Type.IsError() {
		errMap, err := errorMap.GetOrInit(generateErrorMap)
		if err != nil {
			return "", fmt.Errorf("unable to construct error map: %v", err)
		}
		errName, ok := (*errMap)[frame.AddressOrLineno]
		if !ok {
			return "", fmt.Errorf(
				"got invalid error code %d. forgot to `make generate`",
				frame.AddressOrLineno)
		}
		if frame.Type == libpf.AbortFrame {
			return fmt.Sprintf("<unwinding aborted due to error %s>", errName), nil
		}
		return fmt.Sprintf("<error %s>", errName), nil
	}

	if frame.FunctionName != libpf.NullString {
		return fmt.Sprintf("%s+%d in %s:%d",
			frame.FunctionName, frame.FunctionOffset,
			frame.SourceFile, frame.SourceLine), nil
	}

	sourceFile, ok := c.files[frame.FileID]
	if !ok {
		sourceFile = fmt.Sprintf("%08x", frame.FileID)
	}
	return fmt.Sprintf("%s+0x%x", sourceFile, frame.AddressOrLineno), nil
}

func ExtractTraces(ctx context.Context, pr process.Process, debug bool,
	lwpFilter libpf.Set[libpf.PID]) ([]ThreadInfo, error) {
	todo, cancel := context.WithCancel(ctx)
	defer cancel()

	debugFlag := C.int(0)
	if debug {
		debugFlag = 1
	}

	// In host agent we have set the default value for monitorInterval to 5 seconds. But as coredump
	// nor the tests that are calling ExtractTraces() are initializing the reporter package we want
	// to set monitorInterval to a higher value.
	// monitorInterval is used in process manager to collect metrics for every monitorInterval
	// and call functions within the reporter package to report these metrics.
	// So if these functions in the reporter package are called in an uninitialized state the code
	// panics. To avoid these panics we set monitorInterval to a high value so these reporter
	// function are never used.
	monitorInterval := time.Hour * 24

	// Check compatibility.
	pid := pr.PID()
	machineData := pr.GetMachineData()
	goarch := ""
	switch machineData.Machine {
	case elf.EM_X86_64:
		goarch = "amd64"
	case elf.EM_AARCH64:
		goarch = "arm64"
	default:
		return nil, fmt.Errorf("unsupported target %v", machineData.Machine)
	}
	if runtime.GOARCH != goarch {
		return nil, fmt.Errorf("traces must be extracted with a build [%s] of the same "+
			"architecture as the coredump [%s]", runtime.GOARCH, goarch)
	}
	threadInfo, err := pr.GetThreads()
	if err != nil {
		return nil, fmt.Errorf("failed to get thread info for process %d: %v", pid, err)
	}

	// Interfaces for the managers
	ebpfCtx := newEBPFContext(pr)
	defer ebpfCtx.release()

	coredumpEbpfMaps := ebpfMapsCoredump{ctx: ebpfCtx}
	symCache := newSymbolizationCache()

	// Instantiate managers and enable all tracers by default
	includeTracers, _ := tracertypes.Parse("all")

	manager, err := pm.New(todo, includeTracers, monitorInterval, &coredumpEbpfMaps,
		pm.NewMapFileIDMapper(), symCache, elfunwindinfo.NewStackDeltaProvider(), false,
		libpf.Set[string]{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Interpreter manager: %v", err)
	}

	manager.SynchronizeProcess(pr)

	info := make([]ThreadInfo, 0, len(threadInfo))
	for _, thread := range threadInfo {
		if len(lwpFilter) > 0 {
			if _, exists := lwpFilter[libpf.PID(thread.LWP)]; !exists {
				continue
			}
		}

		// Get traces by calling ebpf code via CGO
		ebpfCtx.resetTrace()
		if rc := C.unwind_traces(ebpfCtx.PIDandTGID, debugFlag, C.u64(thread.TPBase),
			unsafe.Pointer(&thread.GPRegs[0])); rc != 0 {
			return nil, fmt.Errorf("failed to unwind lwp %v: %v", thread.LWP, rc)
		}
		// Symbolize traces with interpreter manager
		trace := manager.ConvertTrace(&ebpfCtx.trace)
		tinfo := ThreadInfo{LWP: thread.LWP}
		for _, f := range trace.Frames {
			frame := f.Value()
			frameText, err := symCache.formatFrame(&frame)
			if err != nil {
				return nil, err
			}
			tinfo.Frames = append(tinfo.Frames, frameText)
		}
		info = append(info, tinfo)
	}

	return info, nil
}
