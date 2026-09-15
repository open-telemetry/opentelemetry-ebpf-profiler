package support

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStaticTLSVarInfo(t *testing.T) {
	tests := map[string]struct {
		tlsOffset  uint64
		wantOffset int32
		wantErr    bool
	}{
		// Real resolved value on aarch64 musl, not "unset".
		"zero":         {tlsOffset: 0, wantOffset: 0},
		"negative":     {tlsOffset: ^uint64(0) - 0xf, wantOffset: -0x10},
		"max positive": {tlsOffset: math.MaxInt32, wantOffset: math.MaxInt32},
		"max negative": {tlsOffset: 0xffffffff80000000, wantOffset: math.MinInt32},
		"too positive": {tlsOffset: math.MaxInt32 + 1, wantErr: true},
		"too negative": {tlsOffset: 0xffffffff7fffffff, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tlsVar, err := NewStaticTLSVarInfo(tt.tlsOffset)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, TLSVarInfo{tls_offset: tt.wantOffset, resolved: true}, tlsVar)
		})
	}
}

func TestNewDynamicTLSVarInfo(t *testing.T) {
	tests := map[string]struct {
		moduleID  uint64
		tlsOffset uint64
		want      TLSVarInfo
		wantErr   bool
	}{
		"first": {moduleID: 1, tlsOffset: 0,
			want: TLSVarInfo{module_id: 1}},
		"max module": {moduleID: MaxTLSModuleID, tlsOffset: 8,
			want: TLSVarInfo{tls_offset: 8, module_id: MaxTLSModuleID}},
		"max offset": {moduleID: 1, tlsOffset: math.MaxInt32,
			want: TLSVarInfo{tls_offset: math.MaxInt32, module_id: 1}},
		"module zero":    {moduleID: 0, tlsOffset: 8, wantErr: true},
		"module too big": {moduleID: MaxTLSModuleID + 1, tlsOffset: 8, wantErr: true},
		"offset too big": {moduleID: 1, tlsOffset: math.MaxInt32 + 1, wantErr: true},
		// Rejected, not sign-recovered the way NewStaticTLSVarInfo would.
		"offset negative": {moduleID: 1, tlsOffset: ^uint64(0), wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tlsVar, err := NewDynamicTLSVarInfo(tt.moduleID, tt.tlsOffset)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, tlsVar)
		})
	}
}

func TestSetDTVInfo(t *testing.T) {
	dtv := DTVInfo{Offset: -8, Multiplier: 16}

	v, err := NewDynamicTLSVarInfo(3, 16)
	require.NoError(t, err)

	// A nonzero offset does not make the layout usable, and leaves v untouched.
	require.Error(t, v.SetDTVInfo(DTVInfo{Offset: -8}))
	require.Equal(t, TLSVarInfo{tls_offset: 16, module_id: 3}, v)

	require.NoError(t, v.SetDTVInfo(dtv))
	require.Equal(t,
		TLSVarInfo{tls_offset: 16, module_id: 3, dtv_info: dtv, resolved: true}, v)

	require.Error(t, v.SetDTVInfo(dtv))

	static, err := NewStaticTLSVarInfo(0x10)
	require.NoError(t, err)
	require.Error(t, static.SetDTVInfo(dtv))
}
