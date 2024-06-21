//go:build arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package processmanager

import (
	"fmt"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	sdtypes "github.com/elastic/otel-profiling-agent/nativeunwind/stackdeltatypes"
)

// createVDSOSyntheticRecord creates a generated stack-delta record spanning the entire vDSO binary,
// requesting LR based unwinding. On ARM64, the vDSO currently lacks a proper `.eh_frame` section,
// so we construct it here instead.
// Currently, this assumes that most calls work with the LR unwinding. Special handling
// is added for the signal frame return handler stub which uses signal unwinding.
func createVDSOSyntheticRecord(ef *pfelf.File) sdtypes.IntervalData {
	useLR := sdtypes.UnwindInfo{
		Opcode:   sdtypes.UnwindOpcodeBaseSP,
		FPOpcode: sdtypes.UnwindOpcodeBaseLR,
	}

	deltas := sdtypes.StackDeltaArray{}
	deltas = append(deltas, sdtypes.StackDelta{Address: 0, Info: useLR})
	if sym, err := ef.LookupSymbol("__kernel_rt_sigreturn"); err == nil {
		addr := uint64(sym.Address)
		deltas = append(
			deltas,
			sdtypes.StackDelta{Address: addr, Info: sdtypes.UnwindInfoSignal},
			sdtypes.StackDelta{Address: addr + uint64(sym.Size), Info: useLR},
		)
	}
	return sdtypes.IntervalData{Deltas: deltas}
}

// insertSynthStackDeltas adds synthetic stack-deltas to the given SDMM. On ARM64, this is
// currently only used for emulating proper unwinding info of the vDSO.
func (pm *ProcessManager) insertSynthStackDeltas(fileID host.FileID, ef *pfelf.File) error {
	deltas := createVDSOSyntheticRecord(ef)
	if err := pm.AddSynthIntervalData(fileID, deltas); err != nil {
		return fmt.Errorf("failed to add synthetic deltas: %w", err)
	}
	return nil
}
