// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// insns assembles words into a buffer padded to resolverCodeSize, so that a
// short resolver still reads like one sitting in the middle of a text segment.
func insns(words ...uint32) []byte {
	buf := make([]byte, max(resolverCodeSize, len(words)*instSz))
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*instSz:], w)
	}
	return buf
}

// The real resolvers below are transcribed from aarch64
// ld-linux-aarch64.so.1 (glibc 2.41) and libc.so (musl 1.2.5).
func TestTLSDescReturnsArg(t *testing.T) {
	tests := map[string]struct {
		code []byte
		want bool
	}{
		"glibc _dl_tlsdesc_return": {
			// bti c; ldr x0, [x0, #8]; ret
			code: insns(0xd503245f, 0xf9400400, 0xd65f03c0),
			want: true,
		},
		"musl __tlsdesc_static": {
			// ldr x0, [x0, #8]; ret, byte for byte what bionic and uClibc-ng
			// emit too. The trailing words are __tlsdesc_dynamic, which
			// follows it in musl's text.
			code: insns(0xf9400400, 0xd65f03c0, 0xa9bf0be1, 0xd53bd041),
			want: true,
		},
		"glibc _dl_tlsdesc_dynamic": {
			// bti c; stp x1, x2, [sp, #-32]!; ...
			code: insns(0xd503245f, 0xa9be0be1, 0xa90113e3, 0xd53bd044),
			want: false,
		},
		"wrong descriptor word": {
			// ldr x0, [x0]; ret. Returns the resolver pointer, not the arg.
			code: insns(0xf9400000, 0xd65f03c0),
			want: false,
		},
		"more landing pads than tolerated": {
			// nop; nop; nop; ldr x0, [x0, #8]; ret
			code: insns(0xd503201f, 0xd503201f, 0xd503201f, 0xf9400400, 0xd65f03c0),
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

// Keep the encodings honest about what their comment claims they are.
func TestStaticResolverEncoding(t *testing.T) {
	want := []string{"LDR X0, [X0,#8]", "RET X30"}
	for i, w := range staticResolverBody {
		var b [instSz]byte
		binary.LittleEndian.PutUint32(b[:], w)
		inst, err := arm64asm.Decode(b[:])
		require.NoError(t, err)
		assert.Equal(t, want[i], inst.String())
	}

	for _, hint := range []uint32{
		0xd503201f, // nop
		0xd503241f, // bti
		0xd503245f, // bti c
		0xd503249f, // bti j
		0xd50324df, // bti jc
		0xd503233f, // paciasp
		0xd50323bf, // autiasp
	} {
		assert.True(t, isHint(hint), "%#x", hint)
	}
	for _, w := range staticResolverBody {
		assert.False(t, isHint(w), "%#x", w)
	}
}
