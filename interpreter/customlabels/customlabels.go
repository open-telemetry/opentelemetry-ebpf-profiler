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
	abiVersionExport    = "custom_labels_abi_version"
	currentSetTlsExport = "custom_labels_current_set"
	currentHmTlsExport  = "custom_labels_async_hashmap"
)

var dsoRegex = regexp.MustCompile(`.*/libcustomlabels.*\.so`)
var nodeRegex = regexp.MustCompile(`.*/customlabels\.node`)

type data struct {
	abiVersionElfVA   libpf.Address
	currentSetTlsAddr libpf.Address

	hasCurrentHm     bool
	currentHmTlsAddr libpf.Address

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
	fn := info.FileName()
	isNativeSharedLibrary := dsoRegex.MatchString(fn)
	isNodeExtension := (!isNativeSharedLibrary) && nodeRegex.MatchString(fn)
	isSharedLibrary := isNativeSharedLibrary || isNodeExtension

	var currentSetTlsAddr, currentHmTlsAddr libpf.Address
	var hasCurrentHm bool
	if isSharedLibrary {
		// Resolve thread info TLS export.
		tlsDescs, err := ef.TLSDescriptors()
		if err != nil {
			return nil, errors.New("failed to extract TLS descriptors")
		}
		var ok bool
		currentSetTlsAddr, ok = tlsDescs[currentSetTlsExport]
		if !ok {
			return nil, errors.New("failed to locate TLS descriptor for custom labels")
		}
		if isNodeExtension {
			currentHmTlsAddr, hasCurrentHm = tlsDescs[currentHmTlsExport]
		}
	} else {
		offset, err := ef.LookupTLSSymbolOffset(currentSetTlsExport)
		if err != nil {
			return nil, fmt.Errorf("failed to get tls symbol offset: %w", err)
		}
		currentSetTlsAddr = libpf.Address(offset)
	}

	d := data{
		abiVersionElfVA:   libpf.Address(abiVersionSym.Address),
		currentSetTlsAddr: currentSetTlsAddr,
		hasCurrentHm:      hasCurrentHm,
		currentHmTlsAddr:  currentHmTlsAddr,
		isSharedLibrary:   isSharedLibrary,
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

	var currentSetTlsOffset uint64
	if d.isSharedLibrary {
		// Read TLS offset from the TLS descriptor
		currentSetTlsOffset = rm.Uint64(bias + d.currentSetTlsAddr + 8)
	} else {
		// We're in the main executable: TLS offset is known statically.
		currentSetTlsOffset = uint64(d.currentSetTlsAddr)
	}

	var currentHmTlsOffset uint64
	if d.hasCurrentHm {
		currentHmTlsOffset = rm.Uint64(bias + d.currentHmTlsAddr + 8)
	}

	procInfo := C.NativeCustomLabelsProcInfo{
		current_set_tls_offset: C.u64(currentSetTlsOffset),
		has_current_hm:         C.bool(d.hasCurrentHm),
		current_hm_tls_offset:  C.u64(currentHmTlsOffset),
	}
	if err := ebpf.UpdateProcData(libpf.CustomLabels, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &instance{}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {}

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.CustomLabels, pid)
}
