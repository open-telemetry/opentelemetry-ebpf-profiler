package customlabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/customlabels"

import (
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	abiVersionExport    = "custom_labels_abi_version"
	currentSetTlsExport = "custom_labels_current_set"

	alsIdentityHashExport = "custom_labels_als_identity_hash"
	alsHandleExport       = "custom_labels_als_handle"
)

var dsoRegex = regexp.MustCompile(`.*/libcustomlabels.*\.so`)
var nodeRegex = regexp.MustCompile(`.*/customlabels\.node`)

type data struct {
	abiVersionElfVA   libpf.Address
	currentSetTlsAddr libpf.Address

	hasAlsData          bool
	alsIdentityHashAddr libpf.Address
	alsHandleAddr       libpf.Address

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
		if errors.Is(err, libpf.ErrSymbolNotFound) {
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

	var currentSetTlsAddr libpf.Address
	var alsIdentityHashAddr, alsHandleAddr libpf.Address
	var hasAlsId, hasAlsData bool
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
			alsIdentityHashAddr, hasAlsId = tlsDescs[alsIdentityHashExport]
			if hasAlsId {
				alsHandleAddr, hasAlsData = tlsDescs[alsHandleExport]
			}
		}
	} else {
		offset, err := ef.LookupTLSSymbolOffset(currentSetTlsExport)
		if err != nil {
			return nil, fmt.Errorf("failed to get tls symbol offset: %w", err)
		}
		currentSetTlsAddr = libpf.Address(offset)
	}

	d := data{
		abiVersionElfVA:     libpf.Address(abiVersionSym.Address),
		currentSetTlsAddr:   currentSetTlsAddr,
		isSharedLibrary:     isSharedLibrary,
		hasAlsData:          hasAlsData,
		alsIdentityHashAddr: alsIdentityHashAddr,
		alsHandleAddr:       alsHandleAddr,
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

	var alsIdentityHashTlsOffset, alsHandleTlsOffset uint64
	if d.hasAlsData {
		alsIdentityHashTlsOffset = rm.Uint64(bias + d.alsIdentityHashAddr + 8)
		alsHandleTlsOffset = rm.Uint64(bias + d.alsHandleAddr + 8)
	}

	procInfo := support.NativeCustomLabelsProcInfo{
		Current_set_tls_offset: currentSetTlsOffset,

		Has_als_data:                 d.hasAlsData,
		Als_identity_hash_tls_offset: alsIdentityHashTlsOffset,
		Als_handle_tls_offset:        alsHandleTlsOffset,
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
