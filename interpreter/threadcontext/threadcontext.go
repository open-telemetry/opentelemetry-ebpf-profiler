// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package threadcontext locates the thread context an instrumented process
// publishes through a thread-local pointer, so eBPF can read its trace context
// and labels at unwind time.
package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"debug/elf"
	"errors"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tls"
)

const (
	// tlsExport is the thread-local a process publishes its thread context through.
	tlsExport     = "otel_thread_ctx_v1"
	tlsExportSize = 8
)

func GetLoader(_ Config) interpreter.Loader {
	return interpreter.NewLoader(loader, []interpreter.InterpreterResource{
		{MapName: BPFMapName},
	})
}

func loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// A file without a TLS segment defines no thread-local, so spare it the
	// symbol lookup and the hash table read that comes with it.
	if ef.ProgByType(elf.PT_TLS) == nil {
		return nil, nil
	}

	// Dynamic symbols only: a process publishing a thread context has to export
	// the variable for the profiler to find it. Walking .symtab instead would
	// allocate a Go string per symbol, for every mapped executable and library.
	sym, err := ef.LookupSymbol(tlsExport)
	if err != nil {
		// Absent, or no symbol hash table at all (a fully static executable):
		// either way nothing here publishes a thread context.
		log.Debugf("%s: %s lookup failed: %v", info.FileName(), tlsExport, err)
		return nil, nil
	}
	tlsVar, err := tls.Resolve(ef, sym)
	if err != nil {
		if errors.Is(err, tls.ErrNotThreadLocal) || errors.Is(err, tls.ErrUnsupportedModel) {
			// Not a defect in the file, and not distinguishable from a
			// process that publishes nothing.
			log.Debugf("%s: %s is unreachable: %v", info.FileName(), tlsExport, err)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to resolve %s: %w", tlsExport, err)
	}
	// After Resolve, so only a variable this file defines can fault here.
	if sym.Size != tlsExportSize {
		return nil, fmt.Errorf("%s has wrong size %d", tlsExport, sym.Size)
	}

	log.Debugf("%s: %s is %v", info.FileName(), tlsExport, tlsVar)

	return &threadcontextData{tlsVar: tlsVar}, nil
}

type threadcontextData struct {
	tlsVar tls.Var
}

var _ interpreter.Data = &threadcontextData{}

func (d *threadcontextData) String() string {
	return fmt.Sprintf("Thread context (%v)", d.tlsVar)
}

func (d *threadcontextData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	loc, err := d.tlsVar.Locate(rm, bias)
	if err != nil {
		return nil, fmt.Errorf("failed to locate %s: %w", tlsExport, err)
	}

	tlsInfo, err := loc.VarInfo(libc.DTVInfo{})
	var pendingTLS *tls.VarLocation
	switch {
	case err == nil:
	case errors.Is(err, tls.ErrNeedDTV):
		// Dynamic TLS, so UpdateLibcInfo completes it once the DTV arrives and
		// eBPF skips the read until then.
		pendingTLS = &loc
	default:
		return nil, fmt.Errorf("unusable %s location %v: %w", tlsExport, loc, err)
	}

	procInfo := support.ThreadContextProcInfo{Tls: tlsInfo}
	if err = ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	log.Debugf("PID %d: thread context pointer at %v", pid, loc)

	return &Instance{pendingTLS: pendingTLS}, nil
}

func (d *threadcontextData) Unload(_ interpreter.EbpfHandler) {}

type Instance struct {
	interpreter.InstanceStubs

	// pendingTLS is where the thread context pointer lives while it waits for
	// the DTV layout, nil once described or when there is nothing to wait for.
	pendingTLS *tls.VarLocation
}

var _ interpreter.Instance = &Instance{}

// UpdateLibcInfo completes a thread context pointer in dynamic TLS, which needs
// the DTV layout the process C library defines.
func (i *Instance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID,
	libcInfo libc.LibcInfo,
) error {
	if i.pendingTLS == nil {
		return nil
	}
	if !libcInfo.HasDTVInfo() {
		// May still arrive from a different DSO.
		return nil
	}

	tlsInfo, err := i.pendingTLS.VarInfo(libcInfo.DTVInfo)
	if err != nil {
		return err
	}
	procInfo := support.ThreadContextProcInfo{Tls: tlsInfo}
	if err = ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return err
	}
	i.pendingTLS = nil
	log.Debugf("PID %d: located the thread context pointer via the DTV", pid)
	return nil
}

func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.ThreadContext, pid)
}
