// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libc // import "go.opentelemetry.io/ebpf-profiler/libc"

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type TSDInfo = support.TSDInfo
type DTVInfo = support.DTVInfo

// LibcInfo contains introspection information extracted from the C-library
type LibcInfo struct {
	// TSDInfo is the TSDInfo extracted for this C-library
	TSDInfo TSDInfo
	// DTVInfo contains DTV (Dynamic Thread Vector) introspection data for accessing
	// TLS variables when TLS descriptors are not available
	DTVInfo DTVInfo
}

// IsEqual checks if two LibcInfo instances are equal
func (l LibcInfo) IsEqual(other LibcInfo) bool {
	return l.TSDInfo == other.TSDInfo && l.DTVInfo == other.DTVInfo
}

// Merge fills in empty fields of the receiver with corresponding values from other.
// Fields already populated in the receiver are not overwritten.
func (l *LibcInfo) Merge(other LibcInfo) {
	// If other has TSDInfo and this instance does not, take it
	if l.TSDInfo == (TSDInfo{}) {
		l.TSDInfo = other.TSDInfo
	}

	// If other has DTVInfo and this instance does not, take it
	if l.DTVInfo == (DTVInfo{}) {
		l.DTVInfo = other.DTVInfo
	}
}

// HasTSDInfo returns true if the LibcInfo contains valid TSD information.
// TSDInfo is considered valid when the Multiplier field is non-zero.
func (l LibcInfo) HasTSDInfo() bool {
	return l.TSDInfo.Multiplier != 0
}

// HasDTVInfo returns true if the LibcInfo contains valid DTV information.
// DTVInfo is considered valid when the Multiplier field is non-zero.
func (l LibcInfo) HasDTVInfo() bool {
	return l.DTVInfo.Multiplier != 0
}

var (
	// regex for the libc
	libcRegex = regexp.MustCompile(`.*/(ld-musl|ld-linux|libc|libpthread)([-.].*)?\.so`)
)

// IsPotentialLibcDSO determines if the DSO filename potentially contains libc code
func IsPotentialLibcDSO(filename string) bool {
	return libcRegex.MatchString(filename)
}

func ExtractLibcInfo(ef *pfelf.File) (*LibcInfo, error) {
	info := &LibcInfo{DTVInfo: extractDTVInfo(ef)}

	tsdInfo, tsdErr := extractTSDInfo(ef)
	if tsdErr == nil {
		info.TSDInfo = tsdInfo
	} else if !info.HasDTVInfo() {
		return nil, fmt.Errorf("TSD: %w; no DTV info", tsdErr)
	}

	return info, nil
}

// This code analyzes the C-library provided POSIX defined function which is used
// to read thread-specific data (TSD):
//   void *pthread_getspecific(pthread_key_t key);
//
// The actual symbol and its location is C-library specific:
//
// LIBC			DSO			Symbol
// musl/alpine		ld-musl-$ARCH.so.1	pthread_getspecific
// musl/generic		libc.musl-$ARCH.so.1	pthread_getspecific
// glibc/new		libc.so.6		__pthread_getspecific
// glibc/old		libpthread.so.0		__pthread_getspecific

// musl:
// http://git.musl-libc.org/cgit/musl/tree/src/internal/pthread_impl.h?h=v1.2.3#n49
// http://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_getspecific.c?h=v1.2.3#n4
//
// struct pthread {
//   ...
//   void **tsd;
//   ...
// };
//
// The implementation is just "return self->tsd[key];". We do the same.

// glibc:
// https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/descr.h;hb=c804cd1c00ad#l307
// https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/pthread_getspecific.c;hb=c804cd1c00ad#l23
//
// struct pthread {
//   ...
//   struct pthread_key_data {
//     uintptr_t seq;
//     void *data;
//   } specific_1stblock[PTHREAD_KEY_2NDLEVEL_SIZE];
//   struct pthread_key_data *specific[PTHREAD_KEY_1STLEVEL_SIZE];
//   ...
// }
//
// The disassembly fallback only supports keys smaller than PTHREAD_KEY_2NDLEVEL_SIZE.
// Both x86_64 and arm64 disassemblers assume that small key code is the main
// code flow (as in, any conditional jumps are not followed).
//
// The fallback reads self->specific_1stblock[key].data. With nptl_db metadata,
// we instead follow self->specific[key / block_entries][key % block_entries].data
// for all keys, including the first block.

// extractTSDInfo extracts the introspection data for pthread thread specific data.
func extractTSDInfo(ef *pfelf.File) (TSDInfo, error) {
	// glibc 2.34+ exports layout metadata, avoiding compiler-dependent disassembly.
	if info, err := glibcTSDInfo(ef); err == nil {
		return info, nil
	} else if !errors.Is(err, errNptlDBUnavailable) {
		log.Debugf("Failed to extract glibc TSD metadata, falling back to disassembly: %v", err)
	}

	_, code, err := ef.SymbolData("__pthread_getspecific", 2048)
	if err != nil {
		_, code, err = ef.SymbolData("pthread_getspecific", 2048)
		if err != nil {
			return TSDInfo{}, fmt.Errorf("unable to read 'pthread_getspecific': %s", err)
		}
	}
	if len(code) < 8 {
		return TSDInfo{}, fmt.Errorf("getspecific function size is %d", len(code))
	}

	var info TSDInfo
	switch ef.Machine {
	case elf.EM_AARCH64:
		info, err = extractTSDInfoARM(code)
	case elf.EM_X86_64:
		info, err = extractTSDInfoX86(code)
	default:
		return TSDInfo{}, fmt.Errorf("unsupported arch %s", ef.Machine.String())
	}
	if err != nil {
		return TSDInfo{}, fmt.Errorf("failed to extract getspecific data: %s", err)
	}
	switch libcFlavorOf(ef) {
	case libcGlibc, libcGlibcPthread:
		// The disassembler only recovers access to specific_1stblock.
		info.KeyLimit = 32
	case libcMusl:
		// musl's flat TSD array has PTHREAD_KEYS_MAX entries.
		info.KeyLimit = 128
	default:
		// Cap unknown libc support at glibc's PTHREAD_KEYS_MAX.
		info.KeyLimit = 1024
	}
	return info, nil
}

type libcFlavor int

const (
	libcUnknown libcFlavor = iota
	libcGlibc
	libcGlibcPthread
	libcMusl
)

// Keep libpthread distinct because it can lack nptl_db descriptors even on
// modern glibc. It must not seed DTV constants before libc supplies metadata.
func libcFlavorOf(ef *pfelf.File) libcFlavor {
	// DynString(DT_SONAME) always returns one element, "" when SONAME is absent.
	sonames, err := ef.DynString(elf.DT_SONAME)
	if err != nil {
		return libcUnknown
	}
	for _, soname := range sonames {
		switch {
		case strings.HasPrefix(soname, "libc.musl-"):
			return libcMusl
		case soname == "libc.so.6":
			return libcGlibc
		case soname == "libpthread.so.0":
			return libcGlibcPthread
		case soname != "":
			return libcUnknown
		}
	}
	// Upstream musl has no SONAME. Startup looks up __dls3 by name,
	// so stripping preserves it.
	if sym, err := ef.LookupSymbol("__dls3"); err == nil &&
		sym.Shndx != uint16(elf.SHN_UNDEF) {
		return libcMusl
	}
	return libcUnknown
}

// musl marks the DTV pointer's position as ABI in src/internal/pthread_impl.h:
// after .self on x86_64, and at the end of struct pthread on arm64.
// Verified on musl 1.1.5 through 1.2.5. The .tsd field is outside these ABI
// regions and moves between releases, so TSD still requires disassembly.
//
// glibc's constants cover pre-2.34 releases without exported nptl_db metadata.
// Newer glibc supplies its layout through glibcDTVInfo. Rejected metadata
// must not fall back to constants that may describe a different layout.
var dtvInfos = map[libcFlavor]map[elf.Machine]DTVInfo{
	libcGlibc: {
		elf.EM_X86_64:  {Offset: 8, Multiplier: 16},
		elf.EM_AARCH64: {Offset: 0, Multiplier: 16},
	},
	libcMusl: {
		elf.EM_X86_64:  {Offset: 8, Multiplier: 8},
		elf.EM_AARCH64: {Offset: -8, Multiplier: 8},
	},
}

// Unknown libraries or architectures yield no DTV info.
func extractDTVInfo(ef *pfelf.File) DTVInfo {
	info, err := glibcDTVInfo(ef)
	if err == nil {
		return info
	}
	if !errors.Is(err, errNptlDBUnavailable) {
		log.Debugf("Failed to extract glibc DTV metadata: %v", err)
		// Existing metadata could describe a layout the constants cannot represent.
		return DTVInfo{}
	}
	return dtvInfos[libcFlavorOf(ef)][ef.Machine]
}
