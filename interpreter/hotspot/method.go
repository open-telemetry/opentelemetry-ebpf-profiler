// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hotspot // import "go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"

import (
	"bytes"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// Constants for the JVM internals that have never changed
//
//nolint:golint,stylecheck,revive
const ConstMethod_has_linenumber_table = 0x0001

// hotspotMethod contains symbolization information for one Java method. It caches
// information from Hotspot class Method, the connected class ConstMethod, and
// chasing the pointers in the ConstantPool and other dynamic parts.
type hotspotMethod struct {
	sourceFileName string
	objectID       libpf.FileID
	methodName     string
	bytecodeSize   uint16
	startLineNo    uint16
	lineTable      []byte
}

// Symbolize generates symbolization information for given hotspot method and
// a Byte Code Index (BCI)
func (m *hotspotMethod) symbolize(symbolReporter reporter.SymbolReporter, bci uint32,
	ii *hotspotInstance, trace *libpf.Trace) {
	// Make sure the BCI is within the method range
	if bci >= uint32(m.bytecodeSize) {
		bci = 0
	}

	// Check if this is already known
	frameID := libpf.NewFrameID(m.objectID, libpf.AddressOrLineno(bci))
	trace.AppendFrameID(libpf.HotSpotFrame, frameID)
	if !symbolReporter.FrameKnown(frameID) {
		dec := ii.d.newUnsigned5Decoder(bytes.NewReader(m.lineTable))
		lineNo := dec.mapByteCodeIndexToLine(bci)
		functionOffset := uint32(0)
		if lineNo > uint32(m.startLineNo) {
			functionOffset = lineNo - uint32(m.startLineNo)
		}
		symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
			FrameID:        frameID,
			FunctionName:   m.methodName,
			SourceFile:     m.sourceFileName,
			SourceLine:     libpf.SourceLineno(lineNo),
			FunctionOffset: functionOffset,
		})
	}
}

// hotspotJITInfo contains symbolization and debug information for one JIT compiled
// method or JVM internal stub/function. The main JVM class it extracts the data
// from is class nmethod, and it caches the connected class Method and inlining info.
type hotspotJITInfo struct {
	// compileID is the global unique id (running number) for this code blob
	compileID uint32
	// method contains the Java method data for this JITted instance of it
	method *hotspotMethod
	// scopesPcs contains PC (RIP) to inlining scope mapping information
	scopesPcs []byte
	// scopesData contains information about inlined scopes
	scopesData []byte
	// metadata is the object addresses for the scopes data
	metadata []byte
}

// Symbolize parses JIT method inlining data and fills in symbolization information
// for each inlined method for given RIP.
func (ji *hotspotJITInfo) symbolize(symbolReporter reporter.SymbolReporter, ripDelta int32,
	ii *hotspotInstance, trace *libpf.Trace) error {
	//nolint:lll
	// Unfortunately the data structures read here are not well documented in the JVM
	// source, but for reference implementation you can look:
	// https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/java.base/solaris/native/libjvm_db/libjvm_db.c
	// Search for the functions: get_real_pc(), pc_desc_at(), scope_desc_at() and scopeDesc_chain().

	// Conceptually, the JIT inlining information is kept in scopes_data as a linked
	// list of [ nextScope, methodIndex, byteCodeOffset ] triplets. The innermost scope
	// is resolved by looking it up from a table based on RIP (delta from function start).

	// Loop through the scopes_pcs table to map rip_delta to proper scope.
	// It seems that the first entry is usually [-1, <entry_scope> ] pair,
	// so the below loop needs to handle negative pc_deltas correctly.
	bestPCDelta := int32(-2)
	scopeOff := uint32(0)
	vms := &ii.d.Get().vmStructs
	for i := uint(0); i < uint(len(ji.scopesPcs)); i += vms.PcDesc.Sizeof {
		pcDelta := int32(npsr.Uint32(ji.scopesPcs, i+vms.PcDesc.PcOffset))
		if pcDelta >= bestPCDelta && pcDelta <= ripDelta {
			bestPCDelta = pcDelta
			scopeOff = npsr.Uint32(ji.scopesPcs, i+vms.PcDesc.ScopeDecodeOffset)
			if pcDelta == ripDelta {
				// Exact match of RIP to PC. Stop search.
				// We could also record here that the symbolization
				// result is "accurate"
				break
			}
		}
	}

	if scopeOff == 0 {
		// It is possible that there is no debug info, or no scope information,
		// for the given RIP. In this case we can provide the method name
		// from the metadata.
		ji.method.symbolize(symbolReporter, 0, ii, trace)
		return nil
	}

	// Found scope data. Expand the inlined scope information from it.
	var err error
	maxScopeOff := uint32(len(ji.scopesData))
	for scopeOff != 0 && scopeOff < maxScopeOff {
		// Keep track of the current scope offset, and use it as the next maximum
		// offset. This makes sure the scope offsets decrease monotonically and
		// this loop terminates. It has been verified empirically for this assumption
		// to hold true, and it would be also very difficult for the JVM to generate
		// forward references due to the variable length encoding used.
		maxScopeOff = scopeOff

		// The scope data is three unsigned5 encoded integers
		r := ii.d.newUnsigned5Decoder(bytes.NewReader(ji.scopesData[scopeOff:]))
		scopeOff, err = r.getUint()
		if err != nil {
			return fmt.Errorf("failed to read next scope offset: %v", err)
		}
		methodIdx, err := r.getUint()
		if err != nil {
			return fmt.Errorf("failed to read method index: %v", err)
		}
		byteCodeIndex, err := r.getUint()
		if err != nil {
			return fmt.Errorf("failed to read bytecode index: %v", err)
		}

		if byteCodeIndex > 0 {
			// Analysis shows that the BCI stored in the scopes data
			// is one larger than the BCI used by Interpreter or by
			// the lookup tables. This is probably a bug in the JVM.
			byteCodeIndex--
		}

		if methodIdx != 0 {
			methodPtr := npsr.Ptr(ji.metadata, 8*uint(methodIdx-1))
			method, err := ii.getMethod(methodPtr, 0)
			if err != nil {
				return err
			}
			method.symbolize(symbolReporter, byteCodeIndex, ii, trace)
		}
	}
	return nil
}
