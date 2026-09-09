// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// memory is a sparse address space: a read not fully inside one region fails
// the way an unmapped address does, which is what the models below classify on.
type memory map[uint64][]byte

func (m memory) ReadAt(p []byte, off int64) (int, error) {
	for base, data := range m {
		if uint64(off) >= base && uint64(off)+uint64(len(p)) <= base+uint64(len(data)) {
			copy(p, data[uint64(off)-base:])
			return len(p), nil
		}
	}
	return 0, unix.EFAULT
}

type errReader struct{ err error }

func (r errReader) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func words(vals ...uint64) []byte {
	b := make([]byte, 8*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint64(b[8*i:], v)
	}
	return b
}

// mustStatic and mustDynamic build the expected descriptor through the same
// constructors Locate calls: TLSVarInfo's fields are private, so a literal is
// not available. What that leaves under test here is which model Locate picked
// and the offset it fed in, the constructors themselves being covered by
// support's own tests.
func mustStatic(tlsOffset uint64) VarInfo {
	v, err := support.NewStaticTLSVarInfo(tlsOffset)
	if err != nil {
		panic(err)
	}
	return v
}

func mustDynamic(moduleID, tlsOffset uint64) VarInfo {
	v, err := support.NewDynamicTLSVarInfo(moduleID, tlsOffset)
	if err != nil {
		panic(err)
	}
	return v
}

const (
	bias    = 0x7f0000000000
	elfAddr = 0x1000
	// slotAddr is where the GOT slot or TLS descriptor lands once biased.
	slotAddr = bias + elfAddr
	// indexAddr stands in for the loader's heap allocation, which is where a
	// dynamic descriptor's tls_index lives.
	indexAddr = 0x555555560000
	// lowIndexAddr is that same allocation in a non-PIE process, whose brk heap
	// sits low enough that the address is also a plausible TP-relative offset.
	// This is what leaves the resolver's verdict as the only discriminant.
	lowIndexAddr = 0x420000
	resolverAddr = 0x7f0000100000
)

// staticResolver is musl's __tlsdesc_static / glibc's _dl_tlsdesc_return:
// "ldr x0, [x0, #8]; ret". tlsdesc_aarch64_test.go covers the matching.
var staticResolver = insns(0xf9400400, 0xd65f03c0)

// dynamicResolver opens with musl's __tlsdesc_dynamic "stp x1, x2, [sp, #-16]!",
// so it does not match the static body and the argument decides instead.
var dynamicResolver = insns(0xa9bf0be1, 0xd53bd041, 0xf9400400)

func TestLocate(t *testing.T) {
	tests := map[string]struct {
		v   Var
		mem io.ReaderAt
		// want is compared only when neither error field is set.
		want VarInfo
		// wantErr requires that sentinel. wantAnyErr only requires a failure,
		// for the cases whose error comes from the VarInfo constructors.
		wantErr    error
		wantAnyErr bool
	}{
		"local-exec": {
			v:    Var{access: accessLocalExec, addend: 0x10, variant: variantI},
			want: mustStatic(0x10),
		},
		"initial-exec": {
			v:    Var{access: accessInitialExec, elfAddr: elfAddr, variant: variantI},
			mem:  memory{slotAddr: words(0x20)},
			want: mustStatic(0x20),
		},
		"initial-exec zero offset accepted on aarch64": {
			// Variant I with no PT_TLS in the executable puts musl's first
			// library block at TP+0.
			v:    Var{access: accessInitialExec, elfAddr: elfAddr, variant: variantI},
			mem:  memory{slotAddr: words(0)},
			want: mustStatic(0),
		},
		"initial-exec zero offset rejected on x86-64": {
			v:       Var{access: accessInitialExec, elfAddr: elfAddr, variant: variantII},
			mem:     memory{slotAddr: words(0)},
			wantErr: ErrUnresolved,
		},
		"initial-exec on x86-64": {
			v:    Var{access: accessInitialExec, elfAddr: elfAddr, variant: variantII},
			mem:  memory{slotAddr: words(^uint64(0x10) + 1)},
			want: mustStatic(^uint64(0x10) + 1),
		},
		"initial-exec unreadable slot": {
			v:       Var{access: accessInitialExec, elfAddr: elfAddr, variant: variantI},
			wantErr: unix.EFAULT,
		},
		"general-dynamic": {
			v:    Var{access: accessGeneralDynamic, elfAddr: elfAddr, variant: variantII},
			mem:  memory{slotAddr: words(3, 0x40)},
			want: mustDynamic(3, 0x40),
		},
		"general-dynamic with an unapplied relocation": {
			v:          Var{access: accessGeneralDynamic, elfAddr: elfAddr, variant: variantII},
			mem:        memory{slotAddr: words(0, 0x40)},
			wantAnyErr: true,
		},
		"local-dynamic": {
			// The relocation resolves the module only. The offset is static.
			v: Var{access: accessLocalDynamic, elfAddr: elfAddr, addend: 0x18,
				variant: variantII},
			mem:  memory{slotAddr: words(5)},
			want: mustDynamic(5, 0x18),
		},
		"tlsdesc unrelocated": {
			v:       Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem:     memory{slotAddr: words(0, 0x40)},
			wantErr: ErrUnresolved,
		},
		"tlsdesc static on x86-64": {
			// A negative argument is exactly what makes it a TP offset there.
			v:    Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem:  memory{slotAddr: words(resolverAddr, ^uint64(0x28)+1)},
			want: mustStatic(^uint64(0x28) + 1),
		},
		"tlsdesc dynamic on x86-64": {
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem: memory{
				slotAddr:  words(resolverAddr, indexAddr),
				indexAddr: words(2, 0x30),
			},
			want: mustDynamic(2, 0x30),
		},
		"tlsdesc argument is neither on x86-64": {
			// Readable, so the argument is provably no tls_index, and a
			// non-negative one cannot be a TP offset either.
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem: memory{
				slotAddr:  words(resolverAddr, indexAddr),
				indexAddr: words(0, 0x30),
			},
			wantAnyErr: true,
		},
		"tlsdesc tls_index with an implausible module": {
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem: memory{
				slotAddr:  words(resolverAddr, indexAddr),
				indexAddr: words(support.MaxTLSModuleID+1, 0x30),
			},
			wantAnyErr: true,
		},
		"tlsdesc static on aarch64": {
			// A readable tls_index sits at the argument, so dereferencing it
			// would answer dynamic. Only the resolver says otherwise.
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantI},
			mem: memory{
				slotAddr:     words(resolverAddr, lowIndexAddr),
				resolverAddr: staticResolver,
				lowIndexAddr: words(4, 0x50),
			},
			want: mustStatic(lowIndexAddr),
		},
		"tlsdesc local-dynamic on aarch64": {
			// The symbol's own offset is added to whatever the module resolves to.
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, addend: 0x8,
				variant: variantI},
			mem: memory{
				slotAddr:     words(resolverAddr, indexAddr),
				resolverAddr: dynamicResolver,
				indexAddr:    words(4, 0x50),
			},
			want: mustDynamic(4, 0x58),
		},
		"tlsdesc argument too low to be a pointer": {
			// Settled by the value alone, so the resolver is never read: no
			// region is mapped for it here.
			v:    Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantI},
			mem:  memory{slotAddr: words(resolverAddr, 0x60)},
			want: mustStatic(0x60),
		},
		"tlsdesc unreadable resolver": {
			// Above the bound, so the resolver has to answer, and its failed
			// read must not become a static offset.
			v:       Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantI},
			mem:     memory{slotAddr: words(resolverAddr, lowIndexAddr)},
			wantErr: unix.EFAULT,
		},
		"tlsdesc unreadable argument on aarch64": {
			// The non-PIE shape: the argument is a plausible TP offset and a
			// plausible pointer, and the failed read tells us nothing. This is
			// where a fallback to static would fabricate an address.
			v: Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantI},
			mem: memory{
				slotAddr:     words(resolverAddr, lowIndexAddr),
				resolverAddr: dynamicResolver,
			},
			wantErr: unix.EFAULT,
		},
		"unclassified variable": {
			wantErr: ErrUnsupportedModel,
		},
		// A vanished process must not be classified as "the argument is not a
		// pointer": every errno propagates as itself.
		"vanished process": {
			v:       Var{access: accessTLSDesc, elfAddr: elfAddr, variant: variantII},
			mem:     errReader{err: unix.ESRCH},
			wantErr: unix.ESRCH,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mem := tc.mem
			if mem == nil {
				mem = memory{}
			}
			got, err := tc.v.Locate(remotememory.RemoteMemory{ReaderAt: mem}, bias)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.wantAnyErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
