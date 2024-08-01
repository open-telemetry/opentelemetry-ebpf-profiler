/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

// Trace represents a stack trace. Each tuple (Files[i], Linenos[i]) represents a
// stack frame via the file ID and line number at the offset i in the trace. The
// information for the most recently called function is at offset 0.
type Trace struct {
	Files              []FileID
	Linenos            []AddressOrLineno
	FrameTypes         []FrameType
	MappingStart       []Address
	MappingEnd         []Address
	MappingFileOffsets []uint64
	Hash               TraceHash
	CustomLabels       map[string]string
}

// AppendFrame appends a frame to the columnar frame array without mapping information.
func (trace *Trace) AppendFrame(ty FrameType, file FileID, addrOrLine AddressOrLineno) {
	trace.AppendFrameFull(ty, file, addrOrLine, 0, 0, 0)
}

// AppendFrameFull appends a frame with mapping info to the columnar frame array.
func (trace *Trace) AppendFrameFull(ty FrameType, file FileID, addrOrLine AddressOrLineno,
	mappingStart Address, mappingEnd Address, mappingFileOffset uint64) {
	trace.FrameTypes = append(trace.FrameTypes, ty)
	trace.Files = append(trace.Files, file)
	trace.Linenos = append(trace.Linenos, addrOrLine)
	trace.MappingStart = append(trace.MappingStart, mappingStart)
	trace.MappingEnd = append(trace.MappingEnd, mappingEnd)
	trace.MappingFileOffsets = append(trace.MappingFileOffsets, mappingFileOffset)
}
