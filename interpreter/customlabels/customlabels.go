package customlabels

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"
import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/interpreter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/remotememory"
)

const (
	abiVersionExport = "custom_labels_abi_version"
	tlsExport        = "custom_labels_thread_local_data"
)

var dsoRegex = regexp.MustCompile(`.*/libcustomlabels.*\.so`)

type data struct {
	abiVersionElfVA libpf.Address
	tlsAddr         libpf.Address
	isSharedLibrary bool
}

var _ interpreter.Data = &data{}

func roundUp(multiple, value uint64) uint64 {
	if multiple == 0 {
		return value
	}
	return (value + multiple - 1) / multiple * multiple
}

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
		tlsSym, err := ef.LookupSymbol(tlsExport)
		if err != nil {
			return nil, err
		}
		if ef.Machine == elf.EM_AARCH64 {
			tlsAddr = libpf.Address(tlsSym.Address + 16)
		} else if ef.Machine == elf.EM_X86_64 {
			// Symbol addresses are relative to the start of the
			// thread-local storage image, but the thread pointer points to the _end_
			// of the image. So we need to find the size of the image in order to know where the
			// beginning is.
			//
			// The image is just .tdata followed by .tbss,
			// but we also have to respect the alignment.
			tbss, err := ef.Tbss()
			if err != nil {
				return nil, err
			}
			tdata, err := ef.Tdata()
			var tdataSize uint64
			if err != nil {
				// No Tdata is ok, it's the same as size 0
				if err != pfelf.ErrNoTdata {
					return nil, err
				}
			} else {
				tdataSize = tdata.Size
			}
			imageSize := roundUp(tbss.Addralign, tdataSize) + tbss.Size
			tlsAddr = libpf.Address(int64(tlsSym.Address) - int64(imageSize))
		} else {
			return nil, fmt.Errorf("unrecognized machine: %s", ef.Machine.String())
		}
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

	abiVersionPtr := rm.Ptr(bias + d.abiVersionElfVA)
	abiVersion := rm.Uint32(abiVersionPtr)

	if abiVersion != 0 {
		return nil, fmt.Errorf("unsupported custom labels ABI version: %d"+
			" (only 0 is supported)", abiVersion)
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

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.CustomLabels, pid)
}
