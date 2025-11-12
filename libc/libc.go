// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libc // import "go.opentelemetry.io/ebpf-profiler/libc"

import (
	"debug/elf"
	"fmt"
	"regexp"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type TSDInfo = support.TSDInfo

// LibcInfo contains introspection information extracted from the C-library
type LibcInfo struct {
	// TSDInfo is the TSDInfo extracted for this C-library
	TSDInfo TSDInfo
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
// The 1st block is special cased for keys smaller than PTHREAD_KEY_2NDLEVEL_SIZE.
// We also assume we don't see large keys, and support only the small key case.
// Further both x86_64 and arm64 disassembler assume that small key code is the
// main code flow (as in, any conditional jumps are not followed).
//
// Reading the value is basically "return self->specific_1stblock[key].data;"

var (
	// regex for the libc
	libcRegex = regexp.MustCompile(`.*/(ld-musl|libc|libpthread)([-.].*)?\.so`)
)

// IsPotentialTSDDSO determines if the DSO filename potentially contains pthread code
func IsPotentialTSDDSO(filename string) bool {
	return libcRegex.MatchString(filename)
}

func ExtractLibcInfo(ef *pfelf.File) (*LibcInfo, error) {
	tsdinfo, err := extractTSDInfo(ef)
	if err != nil {
		return nil, err
	}

	return &LibcInfo{
		TSDInfo: tsdinfo,
	}, nil
}

// extractTSDInfo extracts the introspection data for pthread thread specific data.
func extractTSDInfo(ef *pfelf.File) (TSDInfo, error) {
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
	return info, nil
}
