// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// support maps the definitions from headers in the C world into a nice go way
package support // import "go.opentelemetry.io/ebpf-profiler/support"

import (
	"errors"
	"fmt"
	"math"
)

const PIDPageMappingInfoFlagUsesAnonymousMappings = 1 << 0

// EncodeBiasAndUnwindProgram encodes a bias_and_unwind_program value (for C.PIDPageMappingInfo)
// from a bias and unwind program values.
// This currently assumes a non-negative bias: this encoding may have to be changed if bias can be
// negative.
func EncodeBiasAndUnwindProgram(bias uint64,
	unwindProgram uint8) (uint64, error) {
	if (bias >> 56) > 0 {
		return 0, fmt.Errorf("unsupported bias value (too large): 0x%x", bias)
	}
	return bias | (uint64(unwindProgram) << 56), nil
}

// DecodeBiasAndUnwindProgram decodes the contents of the `bias_and_unwind_program` field in
// C.PIDPageMappingInfo and returns the corresponding bias and unwind program.
func DecodeBiasAndUnwindProgram(biasAndUnwindProgram uint64) (bias uint64, unwindProgram uint8) {
	bias = biasAndUnwindProgram & 0x00FFFFFFFFFFFFFF
	unwindProgram = uint8(biasAndUnwindProgram >> 56)
	return bias, unwindProgram
}

// s32TLSOffset narrows a TLS offset to the s32 eBPF stores. x86-64 local-exec
// offsets arrive as a uint64 underflow, so the range check is done on the
// signed reinterpretation.
func s32TLSOffset(tlsOffset uint64) (int32, error) {
	s := int64(tlsOffset)
	offset := int32(s)
	if s != int64(offset) {
		return 0, fmt.Errorf("TLS offset %#x does not fit in s32", tlsOffset)
	}
	return offset, nil
}

// NewStaticTLSVarInfo builds a TLSVarInfo for a variable in static TLS, at a
// TP-relative offset.
func NewStaticTLSVarInfo(tlsOffset uint64) (TLSVarInfo, error) {
	offset, err := s32TLSOffset(tlsOffset)
	if err != nil {
		return TLSVarInfo{}, err
	}
	return TLSVarInfo{tls_offset: offset, resolved: true}, nil
}

// MaxTLSModuleID bounds a plausible TLS module index. IDs are handed out
// sequentially from 1 as objects load, so a larger value was never one.
const MaxTLSModuleID = 0xffff

// NewDynamicTLSVarInfo builds a TLSVarInfo for a variable at tlsOffset within
// module moduleID's TLS block. It stays unresolved until SetDTVInfo supplies
// the layout that libc introspection produces.
func NewDynamicTLSVarInfo(moduleID, tlsOffset uint64) (TLSVarInfo, error) {
	// 0 is static TLS, and an unapplied relocation also reads as 0.
	if moduleID == 0 || moduleID > MaxTLSModuleID {
		return TLSVarInfo{}, fmt.Errorf("implausible TLS module ID %d", moduleID)
	}
	// A position inside the block, so unlike a TP-relative offset never negative.
	if tlsOffset > math.MaxInt32 {
		return TLSVarInfo{}, fmt.Errorf("TLS offset %#x does not fit in s32", tlsOffset)
	}
	return TLSVarInfo{tls_offset: int32(tlsOffset), module_id: uint16(moduleID)}, nil
}

// SetDTVInfo completes a pending descriptor with the DTV layout.
func (v *TLSVarInfo) SetDTVInfo(dtv DTVInfo) error {
	if v.module_id == 0 || v.resolved {
		return errors.New("TLS var is not awaiting the DTV")
	}
	// Multiplier is the DTV entry size, never 0 for a real layout. Same
	// emptiness test as libc.LibcInfo.HasDTVInfo.
	if dtv.Multiplier == 0 {
		return errors.New("empty DTVInfo")
	}
	v.dtv_info = dtv
	v.resolved = true
	return nil
}

// Resolved reports whether the descriptor is complete: static TLS, or dynamic
// with the DTV layout filled in.
func (v TLSVarInfo) Resolved() bool {
	return v.resolved
}

// ModuleID returns the TLS module the variable belongs to, 0 for static TLS.
func (v TLSVarInfo) ModuleID() uint16 {
	return v.module_id
}

// TLSOffset returns the variable's offset: TP-relative for static TLS, from the
// start of the module's TLS block otherwise.
func (v TLSVarInfo) TLSOffset() int32 {
	return v.tls_offset
}
