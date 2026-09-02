// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// insns assembles words into a buffer padded to resolverCodeSize, so that a
// short resolver still reads like one sitting in the middle of a text segment.
func insns(words ...uint32) []byte {
	buf := make([]byte, max(resolverCodeSize, len(words)*4))
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	return buf
}

// The glibc and musl cases below are the real resolvers, transcribed from
// aarch64 ld-linux-aarch64.so.1 (glibc 2.41) and libc.so (musl 1.2.5).
func TestTLSDescReturnsArg(t *testing.T) {
	tests := map[string]struct {
		code []byte
		want bool
	}{
		"glibc _dl_tlsdesc_return": {
			// bti c; ldr x0, [x0, #8]; ret
			code: insns(0xd503245f, 0xf9400400, 0xd65f03c0,
				0xd503245f, 0xf81f0fe1, 0xf9400400),
			want: true,
		},
		"musl __tlsdesc_static": {
			// ldr x0, [x0, #8]; ret
			code: insns(0xf9400400, 0xd65f03c0,
				0xa9bf0be1, 0xd53bd041, 0xf9400400, 0xa9400800),
			want: true,
		},
		"glibc _dl_tlsdesc_dynamic": {
			// bti c; stp x1, x2, [sp, #-32]!; ...
			code: insns(0xd503245f, 0xa9be0be1, 0xa90113e3,
				0xd53bd044, 0xf9400401, 0xf9400080),
			want: false,
		},
		"musl __tlsdesc_dynamic": {
			// stp x1, x2, [sp, #-16]!; mrs x1, tpidr_el0; then the same load
			// __tlsdesc_static uses. Rejected on the opening STP: past it
			// nothing the interpreter models writes x0 again, so the argument
			// would survive to the RET.
			code: insns(0xa9bf0be1, 0xd53bd041, 0xf9400400,
				0xa9400800, 0xcb010042, 0xf85f8021),
			want: false,
		},
		"glibc _dl_tlsdesc_undefweak": {
			// Returns arg - tp, not arg.
			code: insns(0xd503245f, 0xf81f0fe1, 0xf9400400,
				0xd53bd041, 0xcb010000, 0xf84107e1),
			want: false,
		},
		"argument returned via another register": {
			// ldr x1, [x0, #8]; mov x0, x1; ret. Same semantics, other shape.
			code: insns(0xf9400401, 0xaa0103e0, 0xd65f03c0),
			want: true,
		},
		"unmodeled op clobbers x0": {
			// ldr x0, [x0, #8]; ldp x0, x2, [x0]; ret. The LDP overwrites x0
			// but the interpreter skips it, so without resolverModeledOp the
			// stale argument reaches the RET and reads as static.
			code: insns(0xf9400400, 0xa9400800, 0xd65f03c0),
			want: false,
		},
		"arithmetic on x0 the interpreter drops": {
			// ldr x0, [x0, #8]; sub x0, x0, x1; ret. This is the tail of glibc's
			// _dl_tlsdesc_undefweak. SUB's register-register form leaves x0
			// stale, hence its absence from resolverModeledOp.
			code: insns(0xf9400400, 0xcb010000, 0xd65f03c0),
			want: false,
		},
		"wrong descriptor word": {
			// ldr x0, [x0]; ret. Returns the resolver pointer, not the arg.
			code: insns(0xf9400000, 0xd65f03c0),
			want: false,
		},
		"undecodable": {
			code: insns(0x00000000, 0x00000000),
			want: false,
		},
		"truncated": {
			code: insns(0xf9400400)[:4],
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(tc.code)}
			got, err := tlsdescReturnsArg(rm, 0)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

type errReader struct{ err error }

func (r errReader) ReadAt([]byte, int64) (int, error) { return 0, r.err }

// A vanished process must not be reported as a resolver we failed to identify.
func TestTLSDescReturnsArgProcessGone(t *testing.T) {
	rm := remotememory.RemoteMemory{ReaderAt: errReader{err: unix.ESRCH}}
	_, err := tlsdescReturnsArg(rm, 0)
	require.ErrorIs(t, err, unix.ESRCH)
}
