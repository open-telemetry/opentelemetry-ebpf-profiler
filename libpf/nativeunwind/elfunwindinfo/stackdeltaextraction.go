/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package elfunwindinfo

import (
	"fmt"
	"sort"

	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

const (
	// Some DSOs have few limited .eh_frame FDEs (e.g. PLT), and additional
	// FDEs are in .debug_frame or external debug file. This controls how many
	// intervals are needed to not follow .gnu_debuglink.
	numIntervalsToOmitDebugLink = 20
)

// extractionFilter is used to filter in .eh_frame data when a better source
// is available (.gopclntab).
type extractionFilter struct {
	// start and end contains the virtual address block of code which
	// should be excluded from .eh_frame extraction.
	start, end uintptr

	// ehFrames is true if .eh_frame stack deltas are found
	ehFrames bool

	// golangFrames is true if .gopclntab stack deltas are found
	golangFrames bool

	// unsortedFrames is set if stack deltas from unsorted source are found
	unsortedFrames bool
}

var _ ehframeHooks = &extractionFilter{}

// fdeHook filters out .eh_frame data that is superseded by .gopclntab data
func (f *extractionFilter) fdeHook(_ *cieInfo, fde *fdeInfo) bool {
	if !fde.sorted {
		// Seems .debug_frame sometimes has broken FDEs for zero address
		if fde.ipStart == 0 {
			return false
		}
		f.unsortedFrames = true
	}
	// Parse functions outside the gopclntab area
	if fde.ipStart < f.start || fde.ipStart > f.end {
		// This is here to set the flag only when we have collected at least
		// one stack delta from the relevant source.
		f.ehFrames = true
		return true
	}
	return false
}

// deltaHook is a stub to satisfy ehframeHooks interface
func (f *extractionFilter) deltaHook(uintptr, *vmRegs, sdtypes.StackDelta) {
}

func extractDebugDeltas(elfFile *pfelf.File, elfRef *pfelf.Reference,
	deltas *sdtypes.StackDeltaArray, filter *extractionFilter) error {
	var err error

	// Attempt finding the associated debug information file with .debug_frame,
	// but ignore errors if it's not available; many production systems
	// do not intentionally have debug packages installed.
	debugELF, _ := elfFile.OpenDebugLink(elfRef.FileName(), elfRef)
	if debugELF != nil {
		err = parseDebugFrame(debugELF, elfFile, deltas, filter)
		debugELF.Close()
	}
	return err
}

// Extract takes a filename for a modern ELF file that is accessible
// and provides the stack delta intervals in the interval parameter
func Extract(filename string, interval *sdtypes.IntervalData) error {
	elfRef := pfelf.NewReference(filename, pfelf.SystemOpener)
	defer elfRef.Close()
	return ExtractELF(elfRef, interval)
}

// ExtractELF takes a pfelf.Reference and provides the stack delta
// intervals for it in the interval parameter.
func ExtractELF(elfRef *pfelf.Reference, interval *sdtypes.IntervalData) error {
	elfFile, err := elfRef.GetELF()
	if err != nil {
		return err
	}

	// Parse the stack deltas from the ELF
	deltas := sdtypes.StackDeltaArray{}
	filter := &extractionFilter{}

	if err = parseGoPclntab(elfFile, &deltas, filter); err != nil {
		return fmt.Errorf("failure to parse golang stack deltas: %v", err)
	}
	if err = parseEHFrame(elfFile, &deltas, filter); err != nil {
		return fmt.Errorf("failure to parse eh_frame stack deltas: %v", err)
	}
	if err = parseDebugFrame(elfFile, elfFile, &deltas, filter); err != nil {
		return fmt.Errorf("failure to parse debug_frame stack deltas: %v", err)
	}
	if len(deltas) < numIntervalsToOmitDebugLink {
		// There is only few stack deltas. See if we find the .gnu_debuglink
		// debug information for additional .debug_frame stack deltas.
		if err = extractDebugDeltas(elfFile, elfRef, &deltas, filter); err != nil {
			return fmt.Errorf("failure to parse debug stack deltas: %v", err)
		}
	}

	// If multiple sources were merged, sort them.
	if filter.unsortedFrames || (filter.ehFrames && filter.golangFrames) {
		sort.Slice(deltas, func(i, j int) bool {
			if deltas[i].Address != deltas[j].Address {
				return deltas[i].Address < deltas[j].Address
			}
			// Make sure that the potential duplicate stop delta is sorted
			// after the real delta.
			return deltas[i].Info.Opcode < deltas[j].Info.Opcode
		})

		maxDelta := 0
		for i := 0; i < len(deltas); i++ {
			delta := &deltas[i]
			if maxDelta > 0 {
				// This duplicates the logic from StackDeltaArray.Add()
				// to remove duplicate and redundant stack deltas.
				prev := &deltas[maxDelta-1]
				if prev.Hints&sdtypes.UnwindHintGap != 0 &&
					prev.Address+sdtypes.MinimumGap >= delta.Address {
					// The previous opcode is end-of-function marker, and
					// the gap is not large. Reduce deltas by overwriting it.
					if maxDelta <= 1 || deltas[maxDelta-2].Info != delta.Info {
						*prev = *delta
						continue
					}
					// The delta before end-of-function marker is same as
					// what is being inserted now. Overwrite that.
					prev = &deltas[maxDelta-2]
					maxDelta--
				}
				if prev.Info == delta.Info {
					prev.Hints |= delta.Hints & sdtypes.UnwindHintKeep
					continue
				}
				if prev.Address == delta.Address {
					*prev = *delta
					continue
				}
			}
			deltas[maxDelta] = *delta
			maxDelta++
		}
		deltas = deltas[:maxDelta]
	}

	*interval = sdtypes.IntervalData{
		Deltas: deltas,
	}
	return nil
}
