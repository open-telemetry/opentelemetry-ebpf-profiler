// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package threadcontext locates the thread context an instrumented process
// publishes through a thread-local, so eBPF can read its trace context and
// labels at unwind time.
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
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tls"
)

// tlsExport is a thread-local an instrumented process publishes its thread
// context through.
type tlsExport struct {
	name   libpf.SymbolName
	size   uint64
	schema uint8
}

var tlsExports = [...]tlsExport{
	// OTEP 4947 pointer to the thread context record.
	{name: "otel_thread_ctx_v1", size: 8, schema: support.ThreadCtxSchemaTLSDesc},
	// Node.js discovery struct, per design-docs/01861-nodejs-thread-context.
	{name: "otel_thread_ctx_nodejs_v1", size: 32, schema: support.ThreadCtxSchemaNodeJS},
}

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

	// No TLS segment, no thread-local: skip the symbol lookup.
	if ef.ProgByType(elf.PT_TLS) == nil {
		return nil, nil
	}

	// A process publishes one schema, so the first export found is the one.
	for _, export := range tlsExports {
		data, err := loadExport(ef, export)
		if err != nil {
			return nil, err
		}
		if data != nil {
			log.Debugf("%s: %s is %v", info.FileName(), export.name, data.tlsVar)
			return data, nil
		}
	}
	return nil, nil
}

// loadExport resolves export in ef, or returns nil when ef does not define it.
func loadExport(ef *pfelf.File, export tlsExport) (*threadcontextData, error) {
	// The publisher must export the variable for the profiler to find it.
	sym, err := ef.LookupSymbol(export.name)
	if err != nil {
		if errors.Is(err, libpf.ErrSymbolNotFound) || errors.Is(err, pfelf.ErrNoSymbolHash) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to look up %s: %w", export.name, err)
	}
	// A reference to the variable another module defines, which only a DT_HASH
	// lookup returns.
	if sym.Shndx == uint16(elf.SHN_UNDEF) {
		return nil, nil
	}
	tlsVar, err := tls.Resolve(ef, sym)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", export.name, err)
	}
	if sym.Size != export.size {
		return nil, fmt.Errorf("%s has wrong size %d", export.name, sym.Size)
	}
	return &threadcontextData{tlsVar: tlsVar, export: export}, nil
}

type threadcontextData struct {
	tlsVar tls.Var
	export tlsExport
}

var _ interpreter.Data = &threadcontextData{}

func (d *threadcontextData) String() string {
	return fmt.Sprintf("Thread context %s (%v)", d.export.name, d.tlsVar)
}

func (d *threadcontextData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	// Dynamic TLS remains pending until UpdateLibcInfo supplies the DTV layout.
	tlsInfo, pendingTLS, err := d.tlsVar.Locate(rm, bias)
	if err != nil {
		return nil, fmt.Errorf("failed to locate %s: %w", d.export.name, err)
	}

	procInfo := support.ThreadContextProcInfo{Tls: tlsInfo, Schema: d.export.schema}
	if err = ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	log.Debugf("PID %d: thread context TLS %+v, pending %v", pid, tlsInfo, pendingTLS)

	return &Instance{pendingTLS: pendingTLS, schema: d.export.schema}, nil
}

func (d *threadcontextData) Unload(_ interpreter.EbpfHandler) {}

type Instance struct {
	interpreter.InstanceStubs

	// pendingTLS is non-nil while the DTV layout is awaited.
	pendingTLS *tls.VarLocation
	// schema is the THREAD_CTX_SCHEMA_* value of the located thread-local.
	schema uint8
}

var _ interpreter.Instance = &Instance{}

// UpdateLibcInfo completes a dynamic TLS location once the DTV layout is known.
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
	procInfo := support.ThreadContextProcInfo{Tls: tlsInfo, Schema: i.schema}
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
