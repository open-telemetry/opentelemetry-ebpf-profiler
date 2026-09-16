// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestStaticLoc(t *testing.T) {
	tests := map[string]struct {
		tlsOffset  uint64
		wantOffset int32
		wantErr    bool
	}{
		// Real located value on aarch64 musl, not "unset".
		"zero":         {tlsOffset: 0, wantOffset: 0},
		"negative":     {tlsOffset: ^uint64(0) - 0xf, wantOffset: -0x10},
		"max positive": {tlsOffset: math.MaxInt32, wantOffset: math.MaxInt32},
		"max negative": {tlsOffset: 0xffffffff80000000, wantOffset: math.MinInt32},
		"too positive": {tlsOffset: math.MaxInt32 + 1, wantErr: true},
		"too negative": {tlsOffset: 0xffffffff7fffffff, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			loc, err := staticLoc(tt.tlsOffset)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, VarLocation{Offset: tt.wantOffset}, loc)
		})
	}
}

func TestDynamicLoc(t *testing.T) {
	tests := map[string]struct {
		moduleID  uint64
		tlsOffset uint64
		want      VarLocation
		wantErr   bool
	}{
		"first": {moduleID: 1, tlsOffset: 0, want: VarLocation{ModuleID: 1}},
		"max module": {moduleID: math.MaxUint16, tlsOffset: 8,
			want: VarLocation{ModuleID: math.MaxUint16, Offset: 8}},
		"max offset": {moduleID: 1, tlsOffset: math.MaxInt32,
			want: VarLocation{ModuleID: 1, Offset: math.MaxInt32}},
		"module zero":    {moduleID: 0, tlsOffset: 8, wantErr: true},
		"module too big": {moduleID: math.MaxUint16 + 1, tlsOffset: 8, wantErr: true},
		"offset too big": {moduleID: 1, tlsOffset: math.MaxInt32 + 1, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			loc, err := dynamicLoc(tt.moduleID, tt.tlsOffset)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, loc)
		})
	}
}

func TestVarInfo(t *testing.T) {
	dtv := libc.DTVInfo{Offset: -8, Multiplier: 16}

	// Static TLS needs no layout, and an offset of 0 still yields a valid
	// descriptor.
	info, err := VarLocation{}.VarInfo(libc.DTVInfo{})
	require.NoError(t, err)
	require.Equal(t, support.TLSVarInfo{Valid: true}, info)

	// A nonzero DTV offset does not make the layout usable.
	_, err = VarLocation{ModuleID: 3, Offset: 16}.VarInfo(libc.DTVInfo{Offset: -8})
	require.ErrorIs(t, err, ErrNeedDTV)

	info, err = VarLocation{ModuleID: 3, Offset: 16}.VarInfo(dtv)
	require.NoError(t, err)
	require.Equal(t, support.TLSVarInfo{
		Tls_offset: 16, Dtv_pos: 48, Dtv_offset: -8, Valid: true}, info)
}
