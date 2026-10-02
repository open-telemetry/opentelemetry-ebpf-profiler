// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"errors"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/support"
)

// ErrNeedDTV means the variable is in dynamic TLS, so its descriptor cannot be
// built until libc introspection supplies the DTV layout.
var ErrNeedDTV = errors.New("dynamic TLS needs the DTV layout")

// VarLocation is where a thread-local variable lives in a given process.
type VarLocation struct {
	// ModuleID is the TLS module the variable belongs to, 0 for static TLS and
	// the only static/dynamic discriminant.
	ModuleID uint16
	// Offset is TP-relative when ModuleID is 0, else within the module's TLS
	// block. Signed because variant II puts the static block below TP.
	Offset int32
}

func (l VarLocation) String() string {
	return fmt.Sprintf("module=%d offset=%#x", l.ModuleID, l.Offset)
}

// VarInfo builds the descriptor eBPF follows at unwind time. A static location
// ignores dtv, so an empty one will do. A dynamic location given an empty dtv
// yields ErrNeedDTV.
func (l VarLocation) VarInfo(dtv support.DTVInfo) (support.TLSVarInfo, error) {
	if l.ModuleID == 0 {
		return support.TLSVarInfo{Tls_offset: l.Offset, Valid: true}, nil
	}
	// Multiplier is the DTV entry size, never 0 for a real layout. Same
	// emptiness test as libc.LibcInfo.HasDTVInfo.
	if dtv.Multiplier == 0 {
		return support.TLSVarInfo{}, ErrNeedDTV
	}
	return support.TLSVarInfo{
		Tls_offset: l.Offset,
		Dtv_pos:    uint32(l.ModuleID) * uint32(dtv.Multiplier),
		Dtv_offset: dtv.Offset,
		Valid:      true,
	}, nil
}

// staticLoc narrows a TP-relative offset to the s32 a descriptor holds. x86-64
// local-exec offsets arrive as a uint64 underflow, so the range check is done
// on the signed reinterpretation.
func staticLoc(tlsOffset uint64) (VarLocation, error) {
	s := int64(tlsOffset)
	offset := int32(s)
	if s != int64(offset) {
		return VarLocation{}, fmt.Errorf("TLS offset %#x does not fit in s32", tlsOffset)
	}
	return VarLocation{Offset: offset}, nil
}

// dynamicLoc narrows a module ID and an offset within that module's TLS block,
// both read from loader data structures.
func dynamicLoc(moduleID, tlsOffset uint64) (VarLocation, error) {
	// 0 is static TLS, and an unapplied relocation also reads as 0. IDs are
	// handed out sequentially from 1 as objects load, so a value above the u16
	// a descriptor holds was never one.
	if moduleID == 0 || moduleID > math.MaxUint16 {
		return VarLocation{}, fmt.Errorf("implausible TLS module ID %d", moduleID)
	}
	// A position inside the block, so unlike a TP-relative offset never negative.
	if tlsOffset > math.MaxInt32 {
		return VarLocation{}, fmt.Errorf("TLS offset %#x does not fit in s32", tlsOffset)
	}
	return VarLocation{ModuleID: uint16(moduleID), Offset: int32(tlsOffset)}, nil
}
