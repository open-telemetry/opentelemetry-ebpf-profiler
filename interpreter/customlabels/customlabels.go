package customlabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/customlabels"

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"
import (
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	abiVersionExport = "custom_labels_abi_version"
	tlsExport        = "custom_labels_current_set"
)

var dsoRegex = regexp.MustCompile(`.*/libcustomlabels.*\.so|.*/customlabels\.node`)

type data struct {
	abiVersionElfVA libpf.Address
	tlsAddr         libpf.Address
	isSharedLibrary bool
}

var _ interpreter.Data = &data{}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	abiVersionSym, err := ef.LookupSymbol(abiVersionExport)
	if err != nil {
		if errors.Is(err, pfelf.ErrSymbolNotFound) {
			return nil, nil
		}

		return nil, err
	}

	if abiVersionSym.Size != 4 {
		return nil, fmt.Errorf("abi version export has wrong size %d", abiVersionSym.Size)
	}

	// If this is the libcustomlabels.so library, we are using
	// global-dynamic TLS model and have to look up the TLS descriptor.
	// Otherwise, assume we're the main binary and just look up the
	// symbol.
	isSharedLibrary := dsoRegex.MatchString(info.FileName())
	var tlsAddr libpf.Address
	if isSharedLibrary {
		// Resolve thread info TLS export.
		tlsDescs, err := ef.TLSDescriptors()
		if err != nil {
			return nil, errors.New("failed to extract TLS descriptors")
		}
		var ok bool
		tlsAddr, ok = tlsDescs[tlsExport]
		if !ok {
			return nil, errors.New("failed to locate TLS descriptor for custom labels")
		}
	} else {
		offset, err := ef.LookupTLSSymbolOffset(tlsExport)
		if err != nil {
			return nil, fmt.Errorf("failed to get tls symbol offset: %w", err)
		}
		tlsAddr = libpf.Address(offset)
	}

	d := data{
		abiVersionElfVA: libpf.Address(abiVersionSym.Address),
		tlsAddr:         tlsAddr,
		isSharedLibrary: isSharedLibrary,
	}
	return &d, nil
}

type instance struct {
	interpreter.InstanceStubs
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	abiVersion, err := rm.Uint32Checked(bias + d.abiVersionElfVA)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom labels ABI version: %w", err)
	}

	if abiVersion != 1 {
		return nil, fmt.Errorf("unsupported custom labels ABI version: %d"+
			" (only 1 is supported)", abiVersion)
	}

	var tlsOffset uint64
	if d.isSharedLibrary {
		// Read TLS offset from the TLS descriptor
		tlsOffset = rm.Uint64(bias + d.tlsAddr + 8)
	} else {
		// We're in the main executable: TLS offset is known statically.
		tlsOffset = uint64(d.tlsAddr)
	}

	procInfo := C.NativeCustomLabelsProcInfo{tls_offset: C.u64(tlsOffset)}
	if err := ebpf.UpdateProcData(libpf.CustomLabels, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &instance{}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {}

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.CustomLabels, pid)
}
