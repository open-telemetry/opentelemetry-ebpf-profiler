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
	Files      []FileID
	Linenos    []AddressOrLineno
	FrameTypes []FrameType
	Hash       TraceHash
}

// AppendFrame appends a frame to the columnar frame array.
func (trace *Trace) AppendFrame(ty FrameType, file FileID, addrOrLine AddressOrLineno) {
	trace.FrameTypes = append(trace.FrameTypes, ty)
	trace.Files = append(trace.Files, file)
	trace.Linenos = append(trace.Linenos, addrOrLine)
}
