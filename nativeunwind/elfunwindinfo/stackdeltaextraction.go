// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"debug/elf"
	"fmt"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
)

const (
	// Some DSOs have few limited .eh_frame FDEs (e.g. PLT), and additional
	// FDEs are in .debug_frame or external debug file. This controls how many
	// basic blocks are needed to not follow .gnu_debuglink.
	numBlocksToOmitDebugLink = 8
)

// extractionFilter is used to filter in .eh_frame data when a better source
// is available (.gopclntab).
type extractionFilter struct {
	// start and end contains the virtual address block of code which
	// should be excluded from .eh_frame extraction.
	start, end uintptr

	// entryStart and entryEnd contain the virtual address for the entry
	// stub code with synthesized stack deltas.
	entryStart, entryEnd uintptr

	// ehFrames is true if .eh_frame stack deltas are found
	ehFrames bool

	// golangFrames is true if .gopclntab stack deltas are found
	golangFrames bool
}

var _ ehframeHooks = &extractionFilter{}

// fdeHook filters out .eh_frame data that is superseded by .gopclntab data
func (f *extractionFilter) fdeHook(_ *cieInfo, fde *fdeInfo) bool {
	// Drop FDEs inside the gopclntab area
	if f.start <= fde.ipStart && fde.ipStart+fde.ipLen <= f.end {
		return false
	}
	// Seems .debug_frame sometimes has broken FDEs for zero address
	if fde.ipStart == 0 {
		return false
	}
	// Drop FDEs overlapping with the detected entry stub.
	if fde.ipStart+fde.ipLen > f.entryStart && f.entryEnd >= fde.ipStart {
		return false
	}
	// This is here to set the flag only when we have collected at least
	// one stack delta from the relevant source.
	f.ehFrames = true
	return true
}

// deltaHook is a stub to satisfy ehframeHooks interface
func (f *extractionFilter) deltaHook(uintptr, *vmRegs, sdtypes.UnwindInfo) {
}

// golangHook reports the .gopclntab area
func (f *extractionFilter) golangHook(start, end uintptr) {
	f.start = start
	f.end = end
	f.golangFrames = true
}

// elfExtractor is the main context for parsing stack deltas from an ELF
type elfExtractor struct {
	ref  *pfelf.Reference
	file *pfelf.File

	hooks ehframeHooks

	intervals *sdtypes.IntervalData

	// allowGenericRegs enables generation of unwinding using specific general purpose
	// registers as CFA base. This is possible for code that does not call into other
	// functions that would trash these registers (we cannot recover these registers
	// during unwind). This is currently enabled for openssl libcrypto only.
	allowGenericRegs bool
}

func (ee *elfExtractor) extractDebugDeltas() (err error) {
	// Attempt finding the associated debug information file with .debug_frame,
	// but ignore errors if it's not available; many production systems
	// do not intentionally have debug packages installed.
	debugELF, _ := ee.file.OpenDebugLink(ee.ref.FileName(), ee.ref)
	if debugELF != nil {
		err = ee.parseDebugFrame(debugELF)
		_ = debugELF.Close()
	}
	return err
}

func isLibGenericRegsAllowed(elfFile *pfelf.File) bool {
	if name, err := elfFile.DynString(elf.DT_SONAME); err == nil && len(name) == 1 {
		// Allow generic register CFA for openssl libcrypto, glibc and musl
		n := name[0]
		return strings.HasPrefix(n, "libcrypto.so.") ||
			strings.HasPrefix(n, "libc.so.") ||
			strings.HasPrefix(n, "ld-linux-")
	}
	return false
}

// Extract takes a filename for a modern ELF file that is accessible
// and provides the stack delta intervals in the interval parameter
func Extract(filename string) (*sdtypes.IntervalData, error) {
	elfRef := pfelf.NewReference(filename, pfelf.SystemOpener)
	defer elfRef.Close()
	return ExtractELF(elfRef)
}

// detectEntryCode matches machine code for known entry stubs, and detects its length.
func detectEntryCode(machine elf.Machine, code []byte) int {
	switch machine {
	case elf.EM_X86_64:
		return detectEntryX86(code)
	case elf.EM_AARCH64:
		return detectEntryARM(code)
	default:
		return 0
	}
}

// detectEntry loads the entry stub from the ELF DSO entry and matches it.
func detectEntry(ef *pfelf.File) int {
	if ef.Entry == 0 {
		return 0
	}

	// Typically 52-80 bytes, allow for a bit of variance
	code, err := ef.VirtualMemory(int64(ef.Entry), 128, 128)
	if err != nil {
		return 0
	}
	return detectEntryCode(ef.Machine, code)
}

// ExtractELF takes a pfelf.Reference and provides the stack delta
// intervals for it in the interval parameter.
func ExtractELF(elfRef *pfelf.Reference) (*sdtypes.IntervalData, error) {
	elfFile, err := elfRef.GetELF()
	if err != nil {
		return nil, err
	}
	return extractFile(elfFile, elfRef)
}

// extractFile extracts the elfFile stack deltas and uses the optional elfRef to resolve
// debug link references if needed.
func extractFile(elfFile *pfelf.File, elfRef *pfelf.Reference) (*sdtypes.IntervalData, error) {
	// Parse the stack deltas from the ELF
	intervals := &sdtypes.IntervalData{}
	filter := extractionFilter{}
	ee := elfExtractor{
		ref:              elfRef,
		file:             elfFile,
		intervals:        intervals,
		hooks:            &filter,
		allowGenericRegs: isLibGenericRegsAllowed(elfFile),
	}
	if entryLength := detectEntry(elfFile); entryLength != 0 {
		bb := sdtypes.BasicBlock{
			Start: elfFile.Entry,
			End:   elfFile.Entry + uint64(entryLength),
		}
		bb.Deltas.Add(0, sdtypes.UnwindInfoStop)
		intervals.Add(bb)

		filter.entryStart = uintptr(bb.Start)
		filter.entryEnd = uintptr(bb.End)
		filter.ehFrames = true
	}
	if err := ee.parseGoPclntab(); err != nil {
		return nil, fmt.Errorf("failure to parse golang stack deltas: %v", err)
	}
	if err := ee.parseEHFrame(); err != nil {
		return nil, fmt.Errorf("failure to parse eh_frame stack deltas: %v", err)
	}
	if err := ee.parseDebugFrame(elfFile); err != nil {
		return nil, fmt.Errorf("failure to parse debug_frame stack deltas: %v", err)
	}
	if ee.ref != nil && len(intervals.Blocks) < numBlocksToOmitDebugLink {
		// There is only few stack deltas. See if we find the .gnu_debuglink
		// debug information for additional .debug_frame stack deltas.
		if err := ee.extractDebugDeltas(); err != nil {
			return nil, fmt.Errorf("failure to parse debug stack deltas: %v", err)
		}
	}
	if filter.ehFrames {
		intervals.Sort()
	}
	return intervals, nil
}
