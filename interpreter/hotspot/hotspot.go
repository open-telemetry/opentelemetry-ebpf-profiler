/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hotspot

// Java HotSpot Unwinder support code (works also with Scala using HotSpot)

// nolint:lll
// The code here and in hotspot_tracer.ebpf.c is based on the Java Serviceability Agent (SA) code,
// and the Java DTrace helper code (libjvm_db). Additional insight is taken from
// https://github.com/jvm-profiling-tools/async-profiler/ unwinding parts, as well as various other
// online resources.
//
// Hotspot libjvm.so provides several tables of introspection data (such as the C++ class field
// offsets, struct sizes, etc.). These tables are accessed using several sets of exported symbols.
// The data from these tables is read and used to introspect the in-process JVM data structures.
// However, some additional assumptions are done e.g. the data type of each field, and the some
// aspects of the Interpreter stack layout. Some documentation about this introspection data is
// available at:
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/hotspot/share/runtime/vmStructs.hpp
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/hotspot/share/runtime/vmStructs.cpp
//
// The main references are available at (libjvm_db.c being the main source):
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/java.base/solaris/native/libjvm_db/libjvm_db.c
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/hotspot/cpu/x86/frame_x86.cpp
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/hotspot/os_cpu/linux_x86/thread_linux_x86.cpp
//   https://hg.openjdk.java.net/jdk-updates/jdk14u/file/default/src/hotspot/share/prims/forte.cpp
//   https://github.com/jvm-profiling-tools/async-profiler/blob/master/src/profiler.cpp#L280
//   https://github.com/jvm-profiling-tools/async-profiler/blob/master/src/stackFrame_x64.cpp
//   https://docs.oracle.com/javase/specs/
//
// In effect, the code here duplicates the Hotspot SA code in simple standalone manner that is
// portable across several JDK versions. Additional handling of certain states is done based
// on external resources, so this code should be faster, more portable and accurate than
// the Hotspot SA, or other tools.
//
// Notes about JDK changes (other than differences in introspection data values) which affect
// unwinding (incomplete list). The list items are changes done between the release major versions.
//
//  JDK7 - Tested ok
//   - renamed multiple C++ class names: methodOopDesc -> Method, constMethodOopDesc -> ConstMethod, etc.
//   - due to the above some pointers are not including the sizeof OopDesc, and need to be explicitly added
//   - InstanceKlass._source_file_name (Symbol*) -> _source_file_name_index
//   - nmethod._oops_offset renamed to _metadata_offset
//  JDK8 - Tested ok
//   - Interpreter stack frame layout changed (BCP offset by one machine word)
//   - CodeBlob: _code_offset separated to _code_begin and _code_end
//   - CodeCache: _heap -> _heaps,  global CodeCache boundaries added
//   - CompiledMethod: split off from nmethod
//   - nmethod._scopes_data_offset -> CompiledMethod._scopes_data_begin
//   - nmethod._method -> CompiledMethod._method
//   - nmethod._deoptimize_offset -> CompiledMethod._deopt_handler_begin
//   - Modules introduced (but no introspection data to access those)
//  JDK9 - Tested ok
//  JDK10 - Tested ok
//  JDK11 - Reference, works
//   - Symbol.{_length, _refcount} merged to Symbol._length_and_refcount
//  JDK12 - Tested ok
//   - CompiledMethod smaller, nmethod shifted, works OK
//  JDK13 - Tested ok
//   - nmethod smaller, some members shifted, works OK
//  JDK14 - Tested ok
//   - InstanceKlass.Source_file_name_index moved to ConstantPool
//  JDK15 - Tested ok
//   - GenericGrowableArray renamed to GrowableArrayBase
//  JDK16 - Tested ok
//  JDK17 - Tested ok
//  JDK18 - Tested ok
//  JDK19 - Tested ok
//   - Excluding zero byte from UNSIGNED5 encoding output
//  JDK20 - Tested ok
//
// NOTE: Ahead-Of-Time compilation (AOT) is NOT SUPPORTED. The main complication is that, the AOT
// ELF files are mapped directly to the program virtual space, and contain the code to execute.
// This causes the functions to not be in the Java CodeCache and be invisible for the unwinder.
//
// NOTE: Compressed oops is a feature of HotSpot that reduces the size of pointers to Java objects
// on the heap in many cases (see https://wiki.openjdk.org/display/HotSpot/CompressedOops for more
// details). It is turned on by default for heap sizes smaller than 32GB. However, the unwinder
// is not affected by compressed oops as we don't process objects on the Java heap.
//
// The approach is that code here will read the introspection data tables once for each JVM file
// and configure the important field offsets to eBPF via HotspotProcInfo. The eBPF code will then
// have enough data to unwind any HotSpot function via the JVM debug data. On each frame, the eBPF
// code will store four variables: 1. frame subtype, 2. a pointer, 3. a cookie, and 4. rip/bcp
// delta. The pointer is nmethod* (for JIT frames) or Method* (for Interpreted frames).
//
// Once the frame is received in this module's Symbolize function, the code will read additional
// data from the target process at given pointer. The "cookie" is also used to verify that the data
// at given pointer is still describing the same method as during the eBPF capture time. The read
// data is then further parsed, pointers there are followed by reading additional data as needed.
// Caching is done where possible to avoid reads from the target process via syscalls to reduce CPU
// overhead. Finally there should be enough data to produce symbolized frames.
//
// The above approach is selected because the process of symbolizing a JVM Method requires unbounded
// loops to parse the lineNumber tables and cannot be done in the eBPF code. The implication is that
// the frame values are specific to the process (as it has a pointer in it). Meaning the Trace IDs
// will be different if there's multiple VM instances running same Java application. But the overhead
// is not huge here. This also has the implication that in the very unlikely even of two different
// JVM instances producing identical trace (highly unlikely due to ASLR and the address cookie) the
// count aggregation might incorrectly produce wrong expansion. However, it's more likely that there
// will be trace hash collision due to other factors where the same issue would happen.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/freelru"
	npsr "github.com/elastic/otel-profiling-agent/libpf/nopanicslicereader"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/process"
	"github.com/elastic/otel-profiling-agent/libpf/remotememory"
	"github.com/elastic/otel-profiling-agent/libpf/successfailurecounter"
	"github.com/elastic/otel-profiling-agent/libpf/xsync"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/support"
	log "github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

// #include "../../support/ebpf/types.h"
// #include "../../support/ebpf/frametypes.h"
import "C"

var (
	invalidSymbolCharacters = regexp.MustCompile(`[^A-Za-z0-9_]+`)
	// The following regex is intended to match the HotSpot libjvm.so
	libjvmRegex = regexp.MustCompile(`.*/libjvm\.so`)

	_ interpreter.Data     = &hotspotData{}
	_ interpreter.Instance = &hotspotInstance{}
)

var (
	// The FileID used for intrinsic stub frames
	hotspotStubsFileID = libpf.NewFileID(0x578b, 0x1d)
)

// Constants for the JVM internals that have never changed
// nolint:golint,stylecheck,revive
const ConstMethod_has_linenumber_table = 0x0001

// unsigned5Decoder is a decoder for UNSIGNED5 based byte streams.
type unsigned5Decoder struct {
	// r is the byte reader interface to read from
	r io.ByteReader

	// x is the number of exclusion bytes in encoding (JDK20+)
	x uint8
}

// getUint decodes one "standard" J2SE Pack200 UNSIGNED5 number
func (d *unsigned5Decoder) getUint() (uint32, error) {
	const L = uint8(192)
	x := d.x
	r := d.r

	ch, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if ch < x {
		return 0, fmt.Errorf("byte %#x is in excluded range", ch)
	}

	sum := uint32(ch - x)
	for shift := 6; ch >= L && shift < 30; shift += 6 {
		ch, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		if ch < x {
			return 0, fmt.Errorf("byte %#x is in excluded range", ch)
		}
		sum += uint32(ch-x) << shift
	}
	return sum, nil
}

// getSigned decodes one signed number
func (d *unsigned5Decoder) getSigned() (int32, error) {
	val, err := d.getUint()
	if err != nil {
		return 0, err
	}
	return int32(val>>1) ^ -int32(val&1), nil
}

// decodeLineTableEntry incrementally parses one line-table entry consisting of the source
// line number and a byte code index (BCI) from the decoder. The delta encoded line
// table format is specific to HotSpot VM which compresses the unpacked class file line
// tables during class loading.
func (d *unsigned5Decoder) decodeLineTableEntry(bci, line *uint32) error {
	b, err := d.r.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read line table: %v", err)
	}
	switch b {
	case 0x00: // End-of-Stream
		return io.EOF
	case 0xff: // Escape for long deltas
		val, err := d.getSigned()
		if err != nil {
			return fmt.Errorf("failed to read byte code index delta: %v", err)
		}
		*bci += uint32(val)
		val, err = d.getSigned()
		if err != nil {
			return fmt.Errorf("failed to read line number delta: %v", err)
		}
		*line += uint32(val)
	default: // Short encoded delta
		*bci += uint32(b >> 3)
		*line += uint32(b & 7)
	}
	return nil
}

// mapByteCodeIndexToLine decodes a line table to map a given Byte Code Index (BCI)
// to a line number
func (d *unsigned5Decoder) mapByteCodeIndexToLine(bci int32) libpf.SourceLineno {
	// The line numbers array is a short array of 2-tuples [start_pc, line_number].
	// Not necessarily sorted. Encoded as delta-encoded numbers.
	var curBci, curLine, bestBci, bestLine uint32

	for d.decodeLineTableEntry(&curBci, &curLine) == nil {
		if curBci == uint32(bci) {
			return libpf.SourceLineno(curLine)
		}
		if curBci >= bestBci && curBci < uint32(bci) {
			bestBci = curBci
			bestLine = curLine
		}
	}
	return libpf.SourceLineno(bestLine)
}

// javaBaseTypes maps a basic type signature character to the full type name
var javaBaseTypes = map[byte]string{
	'B': "byte",
	'C': "char",
	'D': "double",
	'F': "float",
	'I': "int",
	'J': "long",
	'S': "short",
	'V': "void",
	'Z': "boolean",
}

// demangleJavaTypeSignature demangles a JavaTypeSignature
func demangleJavaTypeSignature(signature string, sb io.StringWriter) string {
	var i, numArr int
	for i = 0; i < len(signature) && signature[i] == '['; i++ {
		numArr++
	}
	if i >= len(signature) {
		return ""
	}

	typeChar := signature[i]
	i++

	if typeChar == 'L' {
		end := strings.IndexByte(signature, ';')
		if end < 0 {
			return ""
		}
		_, _ = sb.WriteString(strings.ReplaceAll(signature[i:end], "/", "."))
		i = end + 1
	} else if typeStr, ok := javaBaseTypes[typeChar]; ok {
		_, _ = sb.WriteString(typeStr)
	}

	for numArr > 0 {
		_, _ = sb.WriteString("[]")
		numArr--
	}

	if len(signature) > i {
		return signature[i:]
	}
	return ""
}

// demangleJavaSignature demangles a JavaTypeSignature
func demangleJavaMethod(klass, method, signature string) string {
	var sb strings.Builder

	// Name format is specified in
	//  - Java Virtual Machine Specification (JVMS)
	//    https://docs.oracle.com/javase/specs/jvms/se14/jvms14.pdf
	//  - Java Language Specification (JLS)
	//    https://docs.oracle.com/javase/specs/jls/se13/jls13.pdf
	//
	// see: JVMS §4.2 (name encoding), §4.3 (signature descriptors)
	//      JLS §13.1 (name encoding)
	//
	// Scala has additional internal transformations which are not
	// well defined, and have changed between Scala versions.

	// Signature looks like "(argumentsSignatures)returnValueSignature"
	// Check for the parenthesis first.
	end := strings.IndexByte(signature, ')')
	if end < 0 || signature[0] != '(' {
		return ""
	}

	left := demangleJavaTypeSignature(signature[end+1:], &sb)
	if left != "" {
		return ""
	}
	sb.WriteRune(' ')
	sb.WriteString(strings.ReplaceAll(klass, "/", "."))
	sb.WriteRune('.')
	sb.WriteString(method)
	sb.WriteRune('(')
	left = signature[1:end]
	for left != "" {
		left = demangleJavaTypeSignature(left, &sb)
		if left == "" {
			break
		}
		sb.WriteString(", ")
	}
	sb.WriteRune(')')

	return sb.String()
}

// hotspotIntrospectionTable contains the resolved ELF symbols for an introspection table
type hotspotIntrospectionTable struct {
	skipBaseDref               bool
	base, stride               libpf.Address
	typeOffset, fieldOffset    libpf.Address
	valueOffset, addressOffset libpf.Address
}

// resolveSymbols resolves the ELF symbols of the introspection table
func (it *hotspotIntrospectionTable) resolveSymbols(ef *pfelf.File, symNames []string) error {
	symVals := make([]libpf.Address, len(symNames))
	for i, s := range symNames {
		if s == "" {
			continue
		}
		addr, err := ef.LookupSymbolAddress(libpf.SymbolName(s))
		if err != nil {
			return fmt.Errorf("symbol '%v' not found: %w", s, err)
		}
		symVals[i] = libpf.Address(addr)
	}

	it.base, it.stride = symVals[0], symVals[1]
	it.typeOffset, it.fieldOffset = symVals[2], symVals[3]
	it.valueOffset, it.addressOffset = symVals[4], symVals[5]
	return nil
}

// hotspotVMData contains static information from one HotSpot build (libjvm.so).
// It mostly is limited to the introspection data (class sizes and field offsets) and
// the version.
type hotspotVMData struct {
	// err is the permanent error if introspection data is not supported
	err error

	// version is the JDK numeric version. Used in some places to make version specific
	// adjustments to the unwinding process.
	version uint32

	// versionStr is the Hotspot build version string, and can contain additional
	// details such as the distribution name and patch level.
	versionStr string

	// unsigned5X is the number of exclusion bytes used in UNSIGNED5 encoding
	unsigned5X uint8

	// vmStructs reflects the HotSpot introspection data we want to extract
	// from the runtime. It is filled using golang reflection (the struct and
	// field names are used to find the data from the JVM). Thus the structs
	// here are following the JVM naming convention.
	//
	// The comments of .Sizeof like ">xxx" are to signify the size range of the JVM
	// C++ class  and thus the expected value of .Sizeof member. This is mainly to
	// indicate the classes for which uint8 is not enough to hold the offset values
	// for the eBPF code.
	vmStructs struct {
		AbstractVMVersion struct {
			Release     libpf.Address `name:"_s_vm_release"`
			BuildNumber libpf.Address `name:"_vm_build_number"`
		} `name:"Abstract_VM_Version"`
		JdkVersion struct {
			Current libpf.Address `name:"_current"`
		} `name:"JDK_Version"`
		CodeBlob struct {
			Sizeof              uint
			Name                uint `name:"_name"`
			FrameCompleteOffset uint `name:"_frame_complete_offset"`
			FrameSize           uint `name:"_frame_size"`
			// JDK -8: offset, JDK 9+: pointers
			CodeBegin uint `name:"_code_begin,_code_offset"`
			CodeEnd   uint `name:"_code_end,_data_offset"`
		}
		CodeCache struct {
			Heap      libpf.Address `name:"_heap"`
			Heaps     libpf.Address `name:"_heaps"`
			HighBound libpf.Address `name:"_high_bound"`
			LowBound  libpf.Address `name:"_low_bound"`
		}
		CodeHeap struct {
			Sizeof          uint
			Log2SegmentSize uint `name:"_log2_segment_size"`
			Memory          uint `name:"_memory"`
			Segmap          uint `name:"_segmap"`
		}
		CompiledMethod struct { // .Sizeof >200
			Sizeof            uint
			DeoptHandlerBegin uint `name:"_deopt_handler_begin"`
			Method            uint `name:"_method"`
			ScopesDataBegin   uint `name:"_scopes_data_begin"`
		}
		ConstantPool struct {
			Sizeof              uint
			PoolHolder          uint `name:"_pool_holder"`
			SourceFileNameIndex uint `name:"_source_file_name_index"`
		} `name:"ConstantPool,constantPoolOopDesc"`
		ConstMethod struct {
			Sizeof    uint
			Constants uint `name:"_constants"`
			CodeSize  uint `name:"_code_size"`
			// JDK21+: ConstMethod._flags is now a struct with another _flags field
			// https://github.com/openjdk/jdk/commit/316d303c1da550c9589c9be56b65650964e3886b
			Flags          uint `name:"_flags,_flags._flags"`
			NameIndex      uint `name:"_name_index"`
			SignatureIndex uint `name:"_signature_index"`
		} `name:"ConstMethod,constMethodOopDesc"`
		// JDK9-15 structure
		GenericGrowableArray struct {
			Len uint `name:"_len"`
		}
		// JDK16 structure
		GrowableArrayBase struct {
			Len uint `name:"_len"`
		}
		GrowableArrayInt struct {
			Sizeof uint
			Data   uint `name:"_data"`
		} `name:"GrowableArray<int>"`
		HeapBlock struct {
			Sizeof uint
		}
		InstanceKlass struct { // .Sizeof >400
			Sizeof              uint
			SourceFileNameIndex uint `name:"_source_file_name_index"`
			SourceFileName      uint `name:"_source_file_name"` // JDK -7 only
		} `name:"InstanceKlass,instanceKlass"`
		Klass struct { // .Sizeof >200
			Sizeof uint
			Name   uint `name:"_name"`
		}
		Method struct {
			ConstMethod uint `name:"_constMethod"`
		} `name:"Method,methodOopDesc"`
		Nmethod struct { // .Sizeof >256
			Sizeof             uint
			CompileID          uint `name:"_compile_id"`
			MetadataOffset     uint `name:"_metadata_offset,_oops_offset"`
			ScopesPcsOffset    uint `name:"_scopes_pcs_offset"`
			DependenciesOffset uint `name:"_dependencies_offset"`
			OrigPcOffset       uint `name:"_orig_pc_offset"`
			DeoptimizeOffset   uint `name:"_deoptimize_offset"`
			Method             uint `name:"_method"`
			ScopesDataOffset   uint `name:"_scopes_data_offset"` // JDK -8 only
		} `name:"nmethod"`
		OopDesc struct {
			Sizeof uint
		} `name:"oopDesc"`
		PcDesc struct {
			Sizeof            uint
			PcOffset          uint `name:"_pc_offset"`
			ScopeDecodeOffset uint `name:"_scope_decode_offset"`
		}
		StubRoutines struct {
			Sizeof   uint                     // not needed, just keep this out of CatchAll
			CatchAll map[string]libpf.Address `name:"*"`
		}
		Symbol struct {
			Sizeof            uint
			Body              uint `name:"_body"`
			Length            uint `name:"_length"`
			LengthAndRefcount uint `name:"_length_and_refcount"`
		}
		VirtualSpace struct {
			HighBoundary uint `name:"_high_boundary"`
			LowBoundary  uint `name:"_low_boundary"`
		}
	}
}

type hotspotData struct {
	// ELF symbols needed for the introspection data
	typePtrs, structPtrs, jvmciStructPtrs hotspotIntrospectionTable

	// Once protected hotspotVMData
	xsync.Once[hotspotVMData]
}

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
	bciSeen        libpf.Set[uint16]
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

// hotspotInstance contains information about one running HotSpot instance (pid)
type hotspotInstance struct {
	interpreter.InstanceStubs

	// Hotspot symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	// d is the interpreter data from jvm.so (shared between processes)
	d *hotspotData

	// rm is used to access the remote process memory
	rm remotememory.RemoteMemory

	// bias is the ELF DSO load bias
	bias libpf.Address

	// prefixes is list of LPM prefixes added to ebpf maps (to be cleaned up)
	prefixes libpf.Set[lpm.Prefix]

	// addrToSymbol maps a JVM class Symbol address to it's string value
	addrToSymbol *freelru.LRU[libpf.Address, string]

	// addrToMethod maps a JVM class Method to a hotspotMethod which caches
	// the needed data from it.
	addrToMethod *freelru.LRU[libpf.Address, *hotspotMethod]

	// addrToJitInfo maps a JVM class nmethod to a hotspotJITInfo which caches
	// the needed data from it.
	addrToJITInfo *freelru.LRU[libpf.Address, *hotspotJITInfo]

	// addrToStubNameID maps a stub name to its unique identifier.
	addrToStubNameID *freelru.LRU[libpf.Address, libpf.AddressOrLineno]

	// mainMappingsInserted stores whether the heap areas and proc data are already populated.
	mainMappingsInserted bool

	// heapAreas stores the top-level JIT areas based on the Java heaps.
	heapAreas []jitArea

	// stubs stores all known stub routine regions.
	stubs map[libpf.Address]StubRoutine
}

// heapInfo contains info about all HotSpot heaps.
type heapInfo struct {
	segmentShift uint32
	ranges       []heapRange
}

// heapRange contains info for an individual heap.
type heapRange struct {
	codeStart, codeEnd     libpf.Address
	segmapStart, segmapEnd libpf.Address
}

type jitArea struct {
	start, end libpf.Address
	codeStart  libpf.Address
	tsid       uint64
}

func (d *hotspotInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToSymbolStats := d.addrToSymbol.GetAndResetStatistics()
	addrToMethodStats := d.addrToMethod.GetAndResetStatistics()
	addrToJITInfoStats := d.addrToJITInfo.GetAndResetStatistics()
	addrToStubNameIDStats := d.addrToStubNameID.GetAndResetStatistics()

	return []metrics.Metric{
		{
			ID:    metrics.IDHotspotSymbolizationSuccesses,
			Value: metrics.MetricValue(d.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDHotspotSymbolizationFailures,
			Value: metrics.MetricValue(d.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDHotspotAddrToSymbolHit,
			Value: metrics.MetricValue(addrToSymbolStats.Hit),
		},
		{
			ID:    metrics.IDHotspotAddrToSymbolMiss,
			Value: metrics.MetricValue(addrToSymbolStats.Miss),
		},
		{
			ID:    metrics.IDHotspotAddrToSymbolAdd,
			Value: metrics.MetricValue(addrToSymbolStats.Added),
		},
		{
			ID:    metrics.IDHotspotAddrToSymbolDel,
			Value: metrics.MetricValue(addrToSymbolStats.Deleted),
		},
		{
			ID:    metrics.IDHotspotAddrToMethodHit,
			Value: metrics.MetricValue(addrToMethodStats.Hit),
		},
		{
			ID:    metrics.IDHotspotAddrToMethodMiss,
			Value: metrics.MetricValue(addrToMethodStats.Miss),
		},
		{
			ID:    metrics.IDHotspotAddrToMethodAdd,
			Value: metrics.MetricValue(addrToMethodStats.Added),
		},
		{
			ID:    metrics.IDHotspotAddrToMethodDel,
			Value: metrics.MetricValue(addrToMethodStats.Deleted),
		},
		{
			ID:    metrics.IDHotspotAddrToJITInfoHit,
			Value: metrics.MetricValue(addrToJITInfoStats.Hit),
		},
		{
			ID:    metrics.IDHotspotAddrToJITInfoMiss,
			Value: metrics.MetricValue(addrToJITInfoStats.Miss),
		},
		{
			ID:    metrics.IDHotspotAddrToJITInfoAdd,
			Value: metrics.MetricValue(addrToJITInfoStats.Added),
		},
		{
			ID:    metrics.IDHotspotAddrToJITInfoDel,
			Value: metrics.MetricValue(addrToJITInfoStats.Deleted),
		},
		{
			ID:    metrics.IDHotspotAddrToStubNameIDHit,
			Value: metrics.MetricValue(addrToStubNameIDStats.Hit),
		},
		{
			ID:    metrics.IDHotspotAddrToStubNameIDMiss,
			Value: metrics.MetricValue(addrToStubNameIDStats.Miss),
		},
		{
			ID:    metrics.IDHotspotAddrToStubNameIDAdd,
			Value: metrics.MetricValue(addrToStubNameIDStats.Added),
		},
		{
			ID:    metrics.IDHotspotAddrToStubNameIDDel,
			Value: metrics.MetricValue(addrToStubNameIDStats.Deleted),
		},
	}, nil
}

// getSymbol extracts a class Symbol value from the given address in the target JVM process
func (d *hotspotInstance) getSymbol(addr libpf.Address) string {
	if value, ok := d.addrToSymbol.Get(addr); ok {
		return value
	}
	vms := d.d.Get().vmStructs

	// Read the symbol length and readahead bytes in attempt to avoid second
	// system call to read the target string. 128 is chosen arbitrarily as "hopefully
	// good enough"; this value can be increased if it turns out to be necessary.
	var buf [128]byte
	if d.rm.Read(addr, buf[:]) != nil {
		return ""
	}
	symLen := npsr.Uint16(buf[:], vms.Symbol.Length)
	if symLen == 0 {
		return ""
	}

	// Always allocate the string separately so it does not hold the backing
	// buffer that might be larger than needed
	tmp := make([]byte, symLen)
	copy(tmp, buf[vms.Symbol.Body:])
	if vms.Symbol.Body+uint(symLen) > uint(len(buf)) {
		prefixLen := uint(len(buf[vms.Symbol.Body:]))
		if d.rm.Read(addr+libpf.Address(vms.Symbol.Body+prefixLen), tmp[prefixLen:]) != nil {
			return ""
		}
	}
	s := string(tmp)
	if !libpf.IsValidString(s) {
		log.Debugf("Extracted Hotspot symbol is invalid at 0x%x '%v'", addr, []byte(s))
		return ""
	}
	d.addrToSymbol.Add(addr, s)
	return s
}

// getPoolSymbol reads a class ConstantPool value from given index, and reads the
// symbol value it is referencing
func (d *hotspotInstance) getPoolSymbol(addr libpf.Address, ndx uint16) string {
	// Zero index is not valid
	if ndx == 0 {
		return ""
	}

	vms := &d.d.Get().vmStructs
	offs := libpf.Address(vms.ConstantPool.Sizeof) + 8*libpf.Address(ndx)
	cpoolVal := d.rm.Ptr(addr + offs)
	// The lowest bit is reserved by JVM to indicate if the value has been
	// resolved or not. The values see should be always resolved.
	// Just ignore the bit as it's meaning has changed between JDK versions.
	return d.getSymbol(cpoolVal &^ 1)
}

// getStubNameID read the stub name from the code blob at given address and generates a ID.
func (d *hotspotInstance) getStubNameID(symbolizer interpreter.Symbolizer, ripOrBci int32,
	addr libpf.Address, _ uint32) (libpf.AddressOrLineno, error) {
	if value, ok := d.addrToStubNameID.Get(addr); ok {
		return value, nil
	}
	vms := &d.d.Get().vmStructs
	constStubNameAddr := d.rm.Ptr(addr + libpf.Address(vms.CodeBlob.Name))
	stubName := d.rm.String(constStubNameAddr)

	a := d.rm.Ptr(addr+libpf.Address(vms.CodeBlob.CodeBegin)) + libpf.Address(ripOrBci)
	for _, stub := range d.stubs {
		if stub.start <= a && stub.end > a {
			stubName = fmt.Sprintf("%s [%s]", stubName, stub.name)
			break
		}
	}

	h := fnv.New128a()
	_, _ = h.Write([]byte(stubName))
	nameHash := h.Sum(nil)
	stubID := libpf.AddressOrLineno(npsr.Uint64(nameHash, 0))

	symbolizer.FrameMetadata(hotspotStubsFileID, stubID, 0, 0, stubName, "")

	d.addrToStubNameID.Add(addr, stubID)
	return stubID, nil
}

// getMethod reads and returns the interesting data from "class Method" at given address
func (d *hotspotInstance) getMethod(addr libpf.Address, _ uint32) (*hotspotMethod, error) {
	if value, ok := d.addrToMethod.Get(addr); ok {
		return value, nil
	}
	vms := &d.d.Get().vmStructs
	constMethodAddr := d.rm.Ptr(addr + libpf.Address(vms.Method.ConstMethod))
	constMethod := make([]byte, vms.ConstMethod.Sizeof)
	if err := d.rm.Read(constMethodAddr, constMethod); err != nil {
		return nil, fmt.Errorf("invalid ConstMethod ptr: %v", err)
	}

	cpoolAddr := npsr.Ptr(constMethod, vms.ConstMethod.Constants)
	cpool := make([]byte, vms.ConstantPool.Sizeof)
	if err := d.rm.Read(cpoolAddr, cpool); err != nil {
		return nil, fmt.Errorf("invalid CostantPool ptr: %v", err)
	}

	instanceKlassAddr := npsr.Ptr(cpool, vms.ConstantPool.PoolHolder)
	instanceKlass := make([]byte, vms.InstanceKlass.Sizeof)
	if err := d.rm.Read(instanceKlassAddr, instanceKlass); err != nil {
		return nil, fmt.Errorf("invalid ConstantPool ptr: %v", err)
	}

	var sourceFileName string
	if vms.ConstantPool.SourceFileNameIndex != 0 {
		// JDK15
		sourceFileName = d.getPoolSymbol(cpoolAddr,
			npsr.Uint16(cpool, vms.ConstantPool.SourceFileNameIndex))
	} else if vms.InstanceKlass.SourceFileNameIndex != 0 {
		// JDK8-14
		sourceFileName = d.getPoolSymbol(cpoolAddr,
			npsr.Uint16(instanceKlass, vms.InstanceKlass.SourceFileNameIndex))
	} else {
		// JDK7
		sourceFileName = d.getSymbol(
			npsr.Ptr(instanceKlass, vms.InstanceKlass.SourceFileName))
	}
	if sourceFileName == "" {
		// Java and Scala can autogenerate lambdas which have no source
		// information available. The HotSpot VM backtraces displays
		// "Unknown Source" as the filename for these.
		sourceFileName = interpreter.UnknownSourceFile
	}

	klassName := d.getSymbol(npsr.Ptr(instanceKlass, vms.Klass.Name))
	methodName := d.getPoolSymbol(cpoolAddr, npsr.Uint16(constMethod,
		vms.ConstMethod.NameIndex))
	signature := d.getPoolSymbol(cpoolAddr, npsr.Uint16(constMethod,
		vms.ConstMethod.SignatureIndex))

	// Synthesize a FileID that is unique to this Class/Method that can be
	// used as "CodeObjectID" value in the trace as frames FileID.
	// Keep the sourcefileName there to start with, and add klass name, method
	// name, byte code and the JVM presentation of the source line table.
	h := fnv.New128a()
	_, _ = h.Write([]byte(sourceFileName))
	_, _ = h.Write([]byte(klassName))
	_, _ = h.Write([]byte(methodName))
	_, _ = h.Write([]byte(signature))

	// Read the byte code for CodeObjectID
	bytecodeSize := npsr.Uint16(constMethod, vms.ConstMethod.CodeSize)
	byteCode := make([]byte, bytecodeSize)
	err := d.rm.Read(constMethodAddr+libpf.Address(vms.ConstMethod.Sizeof), byteCode)
	if err != nil {
		return nil, fmt.Errorf("invalid ByteCode ptr: %v", err)
	}

	_, _ = h.Write(byteCode)

	var lineTable []byte
	startLine := ^uint32(0)
	// NOTE: ConstMethod.Flags is either u16 or u32 depending on JVM version. Since we
	//       only care about flags in the first byte and only operate on little endian
	//       architectures we can get away with reading it as u8 either way.
	if npsr.Uint8(constMethod, vms.ConstMethod.Flags)&ConstMethod_has_linenumber_table != 0 {
		// The line number table size is not known ahead of time. It is delta compressed,
		// so read it once using buffered read to capture it fully. Get also the smallest
		// line number present as the function start line number - this is not perfect
		// as it's the first line for which code was generated. Usually one or few lines
		// after the actual function definition line. The Byte Code Index (BCI) is just
		// used for additional method ID hash input.
		var pcLineEntry [4]byte
		var curBci, curLine uint32
		err = nil
		r := d.rm.Reader(constMethodAddr+libpf.Address(vms.ConstMethod.Sizeof)+
			libpf.Address(bytecodeSize), 256)
		dec := d.d.newUnsigned5Decoder(r)
		for err == nil {
			if curLine > 0 && curLine < startLine {
				startLine = curLine
			}
			err = dec.decodeLineTableEntry(&curBci, &curLine)

			// The BCI and line numbers are read from the target memory in the custom
			// format, but the .class file LineNumberTable is big-endian encoded
			// {
			//   u2 start_pc, line_number;
			// } line_number_table[line_number_table_length]
			//
			// This hashes the line_number_table in .class file format, so if we
			// ever start indexing .class/.java files to match methods to real source
			// file IDs, we can produce the hash in the indexer without additional
			// transformations needed.
			binary.BigEndian.PutUint16(pcLineEntry[0:2], uint16(curBci))
			binary.BigEndian.PutUint16(pcLineEntry[2:4], uint16(curLine))
			_, _ = h.Write(pcLineEntry[:])
		}

		// If EOF encountered, the table was processed successfully.
		if err == io.EOF {
			lineTable = r.GetBuffer()
		}
	}
	if startLine == ^uint32(0) {
		startLine = 0
	}
	// Finalize CodeObjectID generation
	objectID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create a code object ID: %v", err)
	}

	sym := &hotspotMethod{
		sourceFileName: sourceFileName,
		objectID:       objectID,
		methodName:     demangleJavaMethod(klassName, methodName, signature),
		bytecodeSize:   bytecodeSize,
		lineTable:      lineTable,
		startLineNo:    uint16(startLine),
		bciSeen:        make(libpf.Set[uint16]),
	}
	d.addrToMethod.Add(addr, sym)
	return sym, nil
}

// getJITInfo reads and returns the interesting data from "class nmethod" at given address
func (d *hotspotInstance) getJITInfo(addr libpf.Address,
	addrCheck uint32) (*hotspotJITInfo, error) {
	if jit, ok := d.addrToJITInfo.Get(addr); ok {
		if jit.compileID == addrCheck {
			return jit, nil
		}
	}
	vms := &d.d.Get().vmStructs

	// Each JIT-ted function is contained in a "class nmethod"
	// (derived from CompiledMethod and CodeBlob).
	//
	// Layout of important bits in such 'class nmethod' pointer is:
	//	[class CodeBlob fields]
	//	[class CompiledMethod fields]
	//	[class nmethod fields]
	//	...
	//	[JIT_code]	@ this + CodeBlob._code_start
	//	...
	//	[metadata]	@ this + nmethod._metadata_offset	\ these three
	//	[scopes_data]	@ CompiledMethod._scopes_data_begin	| arrays we need
	//	[scopes_pcs]	@ this + nmethod._scopes_pcs_offset	/ for inlining info
	//	[dependencies]	@ this + nmethod._dependencies_offset
	//	...
	//
	// see: src/hotspot/share/code/compiledMethod.hpp
	//      src/hotspot/share/code/nmethod.hpp
	//
	// The scopes_pcs is a look up table to map RIP to scope_data. scopes_data
	// is a list of descriptors that lists the method and it's Byte Code Index (BCI)
	// activations for the scope. Finally the metadata is the array that
	// maps scope_data method indices to real "class Method*".
	nmethod := make([]byte, vms.Nmethod.Sizeof)
	if err := d.rm.Read(addr, nmethod); err != nil {
		return nil, fmt.Errorf("invalid nmethod ptr: %v", err)
	}

	// Since the Java VM might decide recompile or free the JITted nmethods
	// we use the nmethod._compile_id (global running number to identify JIT
	// method) to uniquely identify that we are using the right data here
	// vs. when the pointer was captured by eBPF.
	compileID := npsr.Uint32(nmethod, vms.Nmethod.CompileID)
	if compileID != addrCheck {
		return nil, fmt.Errorf("JIT info evicted since eBPF snapshot")
	}

	// Finally read the associated debug information for this method
	var scopesOff libpf.Address
	metadataOff := npsr.PtrDiff32(nmethod, vms.Nmethod.MetadataOffset)
	if vms.CompiledMethod.ScopesDataBegin != 0 {
		scopesOff = npsr.Ptr(nmethod, vms.CompiledMethod.ScopesDataBegin) - addr
	} else {
		scopesOff = npsr.PtrDiff32(nmethod, vms.Nmethod.ScopesDataOffset)
	}
	scopesPcsOff := npsr.PtrDiff32(nmethod, vms.Nmethod.ScopesPcsOffset)
	depsOff := npsr.PtrDiff32(nmethod, vms.Nmethod.DependenciesOffset)

	if metadataOff > scopesOff || scopesOff > scopesPcsOff || scopesPcsOff > depsOff {
		return nil, fmt.Errorf("unexpected nmethod layout: %v <= %v <= %v <= %v",
			metadataOff, scopesOff, scopesPcsOff, depsOff)
	}

	method, err := d.getMethod(npsr.Ptr(nmethod, vms.CompiledMethod.Method), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get JIT Method: %v", err)
	}

	buf := make([]byte, depsOff-metadataOff)
	if err := d.rm.Read(addr+metadataOff, buf); err != nil {
		return nil, fmt.Errorf("invalid nmethod metadata: %v", err)
	}

	// Buffer is read starting from metadataOff, so adjust accordingly
	scopesOff -= metadataOff
	scopesPcsOff -= metadataOff

	jit := &hotspotJITInfo{
		compileID:  compileID,
		method:     method,
		metadata:   buf[0:scopesOff],
		scopesData: buf[scopesOff:scopesPcsOff],
		scopesPcs:  buf[scopesPcsOff:],
	}

	d.addrToJITInfo.Add(addr, jit)
	return jit, nil
}

// Symbolize generates symbolization information for given hotspot method and
// a Byte Code Index (BCI)
func (m *hotspotMethod) symbolize(symbolizer interpreter.Symbolizer, bci int32,
	ii *hotspotInstance, trace *libpf.Trace) error {
	// Make sure the BCI is within the method range
	if bci < 0 || bci >= int32(m.bytecodeSize) {
		bci = 0
	}
	trace.AppendFrame(libpf.HotSpotFrame, m.objectID, libpf.AddressOrLineno(bci))

	// Check if this is already symbolized
	if _, ok := m.bciSeen[uint16(bci)]; ok {
		return nil
	}

	dec := ii.d.newUnsigned5Decoder(bytes.NewReader(m.lineTable))
	lineNo := dec.mapByteCodeIndexToLine(bci)
	functionOffset := uint32(0)
	if lineNo > libpf.SourceLineno(m.startLineNo) {
		functionOffset = uint32(lineNo) - uint32(m.startLineNo)
	}

	symbolizer.FrameMetadata(m.objectID,
		libpf.AddressOrLineno(bci), lineNo, functionOffset,
		m.methodName, m.sourceFileName)

	// FIXME: The above FrameMetadata call might fail, but we have no idea of it
	// due to the requests being queued and send attempts being done asynchronously.
	// Until the reporting API gets a way to notify failures, just assume it worked.
	m.bciSeen[uint16(bci)] = libpf.Void{}

	log.Debugf("[%d] [%x] %v+%v at %v:%v", len(trace.FrameTypes),
		m.objectID,
		m.methodName, functionOffset,
		m.sourceFileName, lineNo)

	return nil
}

// Symbolize parses JIT method inlining data and fills in symbolization information
// for each inlined method for given RIP.
func (ji *hotspotJITInfo) symbolize(symbolizer interpreter.Symbolizer, ripDelta int32,
	ii *hotspotInstance, trace *libpf.Trace) error {
	// nolint:lll
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
		return ji.method.symbolize(symbolizer, 0, ii, trace)
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
			err = method.symbolize(symbolizer, int32(byteCodeIndex), ii, trace)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Detach removes all information regarding a given process from the eBPF maps.
func (d *hotspotInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	var err error
	if d.mainMappingsInserted {
		err = ebpf.DeleteProcData(libpf.HotSpot, pid)
	}

	for prefix := range d.prefixes {
		if err2 := ebpf.DeletePidInterpreterMapping(pid, prefix); err2 != nil {
			err = multierr.Append(err,
				fmt.Errorf("failed to remove page 0x%x/%d: %v",
					prefix.Key, prefix.Length, err2))
		}
	}

	if err != nil {
		return fmt.Errorf("failed to detach hotspotInstance from PID %d: %v",
			pid, err)
	}
	return nil
}

// gatherHeapInfo collects information about HotSpot heaps.
func (d *hotspotInstance) gatherHeapInfo(vmd *hotspotVMData) (*heapInfo, error) {
	info := &heapInfo{}

	// Determine the location of heap pointers
	var heapPtrAddr libpf.Address
	var numHeaps uint32

	vms := &vmd.vmStructs
	rm := d.rm
	if vms.CodeCache.Heap != 0 {
		// JDK -8: one fixed CodeHeap through fixed pointer
		numHeaps = 1
		heapPtrAddr = vms.CodeCache.Heap + d.bias
	} else {
		// JDK 9-: CodeHeap through _heaps array
		heaps := make([]byte, vms.GrowableArrayInt.Sizeof)
		if err := rm.Read(rm.Ptr(vms.CodeCache.Heaps+d.bias), heaps); err != nil {
			return nil, fmt.Errorf("fail to read heap array: %v", err)
		}
		// Read numHeaps
		numHeaps = npsr.Uint32(heaps, vms.GenericGrowableArray.Len)

		heapPtrAddr = npsr.Ptr(heaps, vms.GrowableArrayInt.Data)
		if numHeaps == 0 || heapPtrAddr == 0 {
			// The heaps are not yet initialized
			return nil, nil
		}
	}

	// Get and sanity check the number of heaps
	if numHeaps < 1 || numHeaps > 16 {
		return nil, fmt.Errorf("bad hotspot heap count (%v)", numHeaps)
	}

	// Extract the heap pointers
	heap := make([]byte, vms.CodeHeap.Sizeof)
	heapPtrs := make([]byte, 8*numHeaps)
	if err := rm.Read(heapPtrAddr, heapPtrs); err != nil {
		return nil, fmt.Errorf("fail to read heap array values: %v", err)
	}

	// Extract each heap structure individually
	for ndx := uint32(0); ndx < numHeaps; ndx++ {
		heapPtr := npsr.Ptr(heapPtrs, uint(ndx*8))
		if heapPtr == 0 {
			// JVM is not initialized yet. Retry later.
			return nil, nil
		}
		if err := rm.Read(heapPtr, heap); err != nil {
			return nil, fmt.Errorf("fail to read heap pointer %d: %v", ndx, err)
		}

		// The segment shift is same for all heaps. So record it for the process only.
		info.segmentShift = npsr.Uint32(heap, vms.CodeHeap.Log2SegmentSize)

		// The LowBoundary and HighBoundary describe the mapping that was reserved
		// with mmap(PROT_NONE). The actual mapping that is committed memory is in
		// VirtualSpace.{Low,High}. However, since we are just following pointers we
		// really care about the maximum values which do not change.
		rng := heapRange{
			codeStart:   npsr.Ptr(heap, vms.CodeHeap.Memory+vms.VirtualSpace.LowBoundary),
			codeEnd:     npsr.Ptr(heap, vms.CodeHeap.Memory+vms.VirtualSpace.HighBoundary),
			segmapStart: npsr.Ptr(heap, vms.CodeHeap.Segmap+vms.VirtualSpace.LowBoundary),
			segmapEnd:   npsr.Ptr(heap, vms.CodeHeap.Segmap+vms.VirtualSpace.HighBoundary),
		}

		// Hook the memory area for HotSpot unwinder
		if rng.codeStart == 0 || rng.codeEnd == 0 {
			return nil, nil
		}

		info.ranges = append(info.ranges, rng)
	}

	return info, nil
}

// addJitArea inserts an entry into the PID<->interpreter BPF map.
func (d *hotspotInstance) addJitArea(ebpf interpreter.EbpfHandler,
	pid libpf.PID, area jitArea) error {
	prefixes, err := lpm.CalculatePrefixList(uint64(area.start), uint64(area.end))
	if err != nil {
		return fmt.Errorf("LPM prefix calculation error for %x-%x", area.start, area.end)
	}

	for _, prefix := range prefixes {
		if _, exists := d.prefixes[prefix]; exists {
			continue
		}

		if err = ebpf.UpdatePidInterpreterMapping(pid, prefix,
			support.ProgUnwindHotspot, host.FileID(area.tsid),
			uint64(area.codeStart)); err != nil {
			return fmt.Errorf(
				"failed to insert LPM entry for pid %d, page 0x%x/%d: %v",
				pid, prefix.Key, prefix.Length, err)
		}

		d.prefixes[prefix] = libpf.Void{}
	}

	log.Debugf("HotSpot jitArea: pid: %d, code %x-%x tsid: %x (%d tries)",
		pid, area.start, area.end, area.tsid, len(prefixes))

	return nil
}

// populateMainMappings populates all important BPF map entries that are available
// immediately after interpreter startup (once VM structs becomes available). This
// allows the BPF code to start unwinding even if some more detailed information
// about e.g. stub routines is not yet available.
func (d *hotspotInstance) populateMainMappings(vmd *hotspotVMData,
	ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	if d.mainMappingsInserted {
		// Already populated: nothing to do here.
		return nil
	}

	heap, err := d.gatherHeapInfo(vmd)
	if err != nil {
		return err
	}
	if heap == nil || len(heap.ranges) == 0 {
		return nil
	}

	// Construct and insert heap areas.
	for _, rng := range heap.ranges {
		tsid := (uint64(rng.segmapStart) & support.HSTSIDSegMapMask) << support.HSTSIDSegMapBit

		area := jitArea{
			start:     rng.codeStart,
			end:       rng.codeEnd,
			codeStart: rng.codeStart,
			tsid:      tsid,
		}

		if err = d.addJitArea(ebpf, pid, area); err != nil {
			return err
		}

		d.heapAreas = append(d.heapAreas, area)
	}

	// Set up the main eBPF info structure.
	vms := &vmd.vmStructs
	procInfo := C.HotspotProcInfo{
		compiledmethod_deopt_handler: C.u16(vms.CompiledMethod.DeoptHandlerBegin),
		nmethod_compileid:            C.u16(vms.Nmethod.CompileID),
		nmethod_orig_pc_offset:       C.u16(vms.Nmethod.OrigPcOffset),
		codeblob_name:                C.u8(vms.CodeBlob.Name),
		codeblob_codestart:           C.u8(vms.CodeBlob.CodeBegin),
		codeblob_codeend:             C.u8(vms.CodeBlob.CodeEnd),
		codeblob_framecomplete:       C.u8(vms.CodeBlob.FrameCompleteOffset),
		codeblob_framesize:           C.u8(vms.CodeBlob.FrameSize),
		cmethod_size:                 C.u8(vms.ConstMethod.Sizeof),
		heapblock_size:               C.u8(vms.HeapBlock.Sizeof),
		method_constmethod:           C.u8(vms.Method.ConstMethod),
		jvm_version:                  C.u8(vmd.version >> 24),
		segment_shift:                C.u8(heap.segmentShift),
	}

	if vms.CodeCache.LowBound == 0 {
		// JDK-8 has only one heap, use its bounds
		procInfo.codecache_start = C.u64(heap.ranges[0].codeStart)
		procInfo.codecache_end = C.u64(heap.ranges[0].codeEnd)
	} else {
		// JDK9+ the VM tracks it separately
		procInfo.codecache_start = C.u64(d.rm.Ptr(vms.CodeCache.LowBound + d.bias))
		procInfo.codecache_end = C.u64(d.rm.Ptr(vms.CodeCache.HighBound + d.bias))
	}

	if err = ebpf.UpdateProcData(libpf.HotSpot, pid, unsafe.Pointer(&procInfo)); err != nil {
		return err
	}

	d.mainMappingsInserted = true
	return nil
}

// updateStubMappings adds new stub routines that are not yet tracked in our
// stubs map and, if necessary on the architecture, inserts unwinding instructions
// for them in the PID mappings BPF map.
func (d *hotspotInstance) updateStubMappings(vmd *hotspotVMData,
	ebpf interpreter.EbpfHandler, pid libpf.PID) {
	for _, stub := range findStubBounds(vmd, d.bias, d.rm) {
		if _, exists := d.stubs[stub.start]; exists {
			continue
		}

		d.stubs[stub.start] = stub

		// Separate stub areas are only required on ARM64.
		if runtime.GOARCH != "arm64" {
			continue
		}

		// Find corresponding heap jitArea.
		var stubHeapArea *jitArea
		for i := range d.heapAreas {
			heapArea := &d.heapAreas[i]
			if stub.start >= heapArea.start && stub.end <= heapArea.end {
				stubHeapArea = heapArea
				break
			}
		}
		if stubHeapArea == nil {
			log.Warnf("Unable to find heap for stub: pid = %d, stub.start = 0x%x",
				pid, stub.start)
			continue
		}

		// Create and insert a jitArea for the stub.
		stubArea, err := jitAreaForStubArm64(&stub, stubHeapArea, d.rm)
		if err != nil {
			log.Warnf("Failed to create JIT area for stub (pid = %d, stub.start = 0x%x): %v",
				pid, stub.start, err)
			continue
		}
		if err = d.addJitArea(ebpf, pid, stubArea); err != nil {
			log.Warnf("Failed to insert JIT area for stub (pid = %d, stub.start = 0x%x): %v",
				pid, stub.start, err)
			continue
		}
	}
}

func (d *hotspotInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, _ []process.Mapping) error {
	vmd, err := d.d.GetOrInit(d.initVMData)
	if err != nil {
		return err
	}

	// Check for permanent errors
	if vmd.err != nil {
		return vmd.err
	}

	// Populate main mappings, if not done previously.
	pid := pr.PID()
	err = d.populateMainMappings(vmd, ebpf, pid)
	if err != nil {
		return err
	}
	if !d.mainMappingsInserted {
		// Not ready yet: try later.
		return nil
	}

	d.updateStubMappings(vmd, ebpf, pid)

	return nil
}

// Symbolize interpreters Hotspot eBPF uwinder given data containing target
// process address and translates it to static IDs expanding any inlined frames
// to multiple new frames. Associated symbolization metadata is extracted and
// queued to be sent to collection agent.
func (d *hotspotInstance) Symbolize(symbolReporter reporter.SymbolReporter,
	frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.HotSpot) {
		return interpreter.ErrMismatchInterpreterType
	}

	// Extract the HotSpot frame bitfields from the file and line variables
	ptr := libpf.Address(frame.File)
	subtype := uint32(frame.Lineno>>60) & 0xf
	ripOrBci := int32(frame.Lineno>>32) & 0x0fffffff
	ptrCheck := uint32(frame.Lineno)

	var err error
	sfCounter := successfailurecounter.New(&d.successCount, &d.failCount)
	defer sfCounter.DefaultToFailure()

	switch subtype {
	case C.FRAME_HOTSPOT_STUB, C.FRAME_HOTSPOT_VTABLE:
		// These are stub frames that may or may not be interesting
		// to be seen in the trace.
		stubID, err1 := d.getStubNameID(symbolReporter, ripOrBci, ptr, ptrCheck)
		if err1 != nil {
			return err
		}
		trace.AppendFrame(libpf.HotSpotFrame, hotspotStubsFileID, stubID)
	case C.FRAME_HOTSPOT_INTERPRETER:
		method, err1 := d.getMethod(ptr, ptrCheck)
		if err1 != nil {
			return err
		}
		err = method.symbolize(symbolReporter, ripOrBci, d, trace)
	case C.FRAME_HOTSPOT_NATIVE:
		jitinfo, err1 := d.getJITInfo(ptr, ptrCheck)
		if err1 != nil {
			return err1
		}
		err = jitinfo.symbolize(symbolReporter, ripOrBci, d, trace)
	default:
		return fmt.Errorf("hotspot frame subtype %v is not supported", subtype)
	}

	if err != nil {
		return err
	}
	sfCounter.ReportSuccess()
	return nil
}

func (d *hotspotData) newUnsigned5Decoder(r io.ByteReader) *unsigned5Decoder {
	return &unsigned5Decoder{
		r: r,
		x: d.Get().unsigned5X,
	}
}

func (d *hotspotData) String() string {
	if vmd := d.Get(); vmd != nil {
		return fmt.Sprintf("Java HotSpot VM %d.%d.%d+%d (%v)",
			(vmd.version>>24)&0xff, (vmd.version>>16)&0xff,
			(vmd.version>>8)&0xff, vmd.version&0xff,
			vmd.versionStr)
	}
	return "<unintrospected JVM>"
}

// Attach loads to the ebpf program the needed pointers and sizes to unwind given hotspot process.
// As the hotspot unwinder depends on the native unwinder, a part of the cleanup is done by the
// process manager and not the corresponding Detach() function of hotspot objects.
func (d *hotspotData) Attach(_ interpreter.EbpfHandler, _ libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (ii interpreter.Instance, err error) {
	// Each function has four symbols: source filename, class name,
	// method name and signature. However, most of them are shared across
	// different methods, so assume about 2 unique symbols per function.
	addrToSymbol, err :=
		freelru.New[libpf.Address, string](2*interpreter.LruFunctionCacheSize,
			libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}
	addrToMethod, err :=
		freelru.New[libpf.Address, *hotspotMethod](interpreter.LruFunctionCacheSize,
			libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}
	addrToJITInfo, err :=
		freelru.New[libpf.Address, *hotspotJITInfo](interpreter.LruFunctionCacheSize,
			libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}
	// In total there are about 100 to 200 intrinsics. We don't expect to encounter
	// everyone single one. So we use a small cache size here than LruFunctionCacheSize.
	addrToStubNameID, err :=
		freelru.New[libpf.Address, libpf.AddressOrLineno](128,
			libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	return &hotspotInstance{
		d:                d,
		rm:               rm,
		bias:             bias,
		addrToSymbol:     addrToSymbol,
		addrToMethod:     addrToMethod,
		addrToJITInfo:    addrToJITInfo,
		addrToStubNameID: addrToStubNameID,
		prefixes:         libpf.Set[lpm.Prefix]{},
		stubs:            map[libpf.Address]StubRoutine{},
	}, nil
}

// fieldByJavaName searches obj for a field by its JVM name using the struct tags.
func fieldByJavaName(obj reflect.Value, fieldName string) reflect.Value {
	var catchAll reflect.Value

	objType := obj.Type()
	for i := 0; i < obj.NumField(); i++ {
		objField := objType.Field(i)
		if nameTag, ok := objField.Tag.Lookup("name"); ok {
			for _, javaName := range strings.Split(nameTag, ",") {
				if fieldName == javaName {
					return obj.Field(i)
				}
				if javaName == "*" {
					catchAll = obj.Field(i)
				}
			}
		}
		if fieldName == objField.Name {
			return obj.Field(i)
		}
	}

	return catchAll
}

// parseIntrospection loads and parses HotSpot introspection tables. It will then fill in
// hotspotData.vmStructs using reflection to gather the offsets and sizes
// we are interested about.
func (vmd *hotspotVMData) parseIntrospection(it *hotspotIntrospectionTable,
	rm remotememory.RemoteMemory, loadBias libpf.Address) error {
	stride := libpf.Address(rm.Uint64(it.stride + loadBias))
	typeOffs := uint(rm.Uint64(it.typeOffset + loadBias))
	addrOffs := uint(rm.Uint64(it.addressOffset + loadBias))
	fieldOffs := uint(rm.Uint64(it.fieldOffset + loadBias))
	valOffs := uint(rm.Uint64(it.valueOffset + loadBias))
	base := it.base + loadBias

	if !it.skipBaseDref {
		base = rm.Ptr(base)
	}

	if base == 0 || stride == 0 {
		return fmt.Errorf("bad introspection table data (%#x / %d)", base, stride)
	}

	// Parse the introspection table
	e := make([]byte, stride)
	vm := reflect.ValueOf(&vmd.vmStructs).Elem()
	for addr := base; true; addr += stride {
		if err := rm.Read(addr, e); err != nil {
			return err
		}

		typeNamePtr := npsr.Ptr(e, typeOffs)
		if typeNamePtr == 0 {
			break
		}

		typeName := rm.String(typeNamePtr)
		f := fieldByJavaName(vm, typeName)
		if !f.IsValid() {
			continue
		}

		// If parsing the Types table, we have sizes. Otherwise, we are
		// parsing offsets for fields.
		fieldName := "Sizeof"
		if it.fieldOffset != 0 {
			fieldNamePtr := npsr.Ptr(e, fieldOffs)
			fieldName = rm.String(fieldNamePtr)
			if fieldName == "" || fieldName[0] != '_' {
				continue
			}
		}

		f = fieldByJavaName(f, fieldName)
		if !f.IsValid() {
			continue
		}

		value := uint64(npsr.Ptr(e, addrOffs))
		if value != 0 {
			// We just resolved a const pointer. Adjust it by loadBias
			// to get a globally cacheable unrelocated virtual address.
			value -= uint64(loadBias)
			log.Debugf("JVM %v.%v = @ %x", typeName, fieldName, value)
		} else {
			// Literal value
			value = npsr.Uint64(e, valOffs)
			log.Debugf("JVM %v.%v = %v", typeName, fieldName, value)
		}

		switch f.Kind() {
		case reflect.Uint64, reflect.Uint:
			f.SetUint(value)
		case reflect.Map:
			if f.IsNil() {
				// maps need explicit init (nil is invalid)
				f.Set(reflect.MakeMap(f.Type()))
			}

			castedValue := reflect.ValueOf(value).Convert(f.Type().Elem())
			f.SetMapIndex(reflect.ValueOf(fieldName), castedValue)
		default:
			panic(fmt.Sprintf("bug: unexpected field type in vmStructs: %v", f.Kind()))
		}
	}
	return nil
}

// forEachItem walks the given struct reflection fields recursively, and calls the visitor
// function for each field item with it's value and name. This does not work with recursively
// linked structs, and is intended currently to be ran with the Hotspot's vmStructs struct only.
// Catch-all fields are ignored and skipped.
func forEachItem(prefix string, t reflect.Value, visitor func(reflect.Value, string) error) error {
	if prefix != "" {
		prefix += "."
	}
	for i := 0; i < t.NumField(); i++ {
		val := t.Field(i)
		fieldName := prefix + t.Type().Field(i).Name
		switch val.Kind() {
		case reflect.Struct:
			if err := forEachItem(fieldName, val, visitor); err != nil {
				return err
			}
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			if err := visitor(val, fieldName); err != nil {
				return err
			}
		case reflect.Map:
			continue
		default:
			panic("unsupported type")
		}
	}
	return nil
}

// initVMData will fill hotspotVMData introspection data on first use
func (d *hotspotInstance) initVMData() (hotspotVMData, error) {
	// Initialize the data with non-zero values so it's easy to check that
	// everything got loaded (some fields will get zero values)
	vmd := hotspotVMData{}
	rm := d.rm
	bias := d.bias
	_ = forEachItem("", reflect.ValueOf(&vmd.vmStructs).Elem(),
		func(item reflect.Value, name string) error {
			item.SetUint(^uint64(0))
			return nil
		})

	// First load the sizes of the classes
	if err := vmd.parseIntrospection(&d.d.typePtrs, d.rm, bias); err != nil {
		return vmd, err
	}
	// And the field offsets and static values
	if err := vmd.parseIntrospection(&d.d.structPtrs, d.rm, bias); err != nil {
		return vmd, err
	}
	if d.d.jvmciStructPtrs.base != 0 {
		if err := vmd.parseIntrospection(&d.d.jvmciStructPtrs, d.rm, bias); err != nil {
			return vmd, err
		}
	}

	// Failures after this point are permanent
	vms := &vmd.vmStructs
	jdkVersion := rm.Uint32(vms.JdkVersion.Current + bias)
	major := jdkVersion & 0xff
	minor := (jdkVersion >> 8) & 0xff
	patch := (jdkVersion >> 16) & 0xff
	build := rm.Uint32(vms.AbstractVMVersion.BuildNumber + bias)
	vmd.version = major<<24 + minor<<16 + patch<<8 + build
	vmd.versionStr = rm.StringPtr(vms.AbstractVMVersion.Release + bias)

	// Check minimum supported version. JDK 7-20 supported. Assume newer JDK
	// works if the needed symbols are found.
	if major < 7 {
		vmd.err = fmt.Errorf("JVM version %d.%d.%d+%d (minimum is 7)",
			major, minor, patch, build)
		return vmd, nil
	}

	if vms.ConstantPool.SourceFileNameIndex != ^uint(0) {
		// JDK15: Use ConstantPool.SourceFileNameIndex
		vms.InstanceKlass.SourceFileNameIndex = 0
		vms.InstanceKlass.SourceFileName = 0
	} else if vms.InstanceKlass.SourceFileNameIndex != ^uint(0) {
		// JDK8-14: Use InstanceKlass.SourceFileNameIndex
		vms.ConstantPool.SourceFileNameIndex = 0
		vms.InstanceKlass.SourceFileName = 0
	} else {
		// JDK7: File name is direct Symbol*, adjust offsets with OopDesc due
		// to the base pointer type changes
		vms.InstanceKlass.SourceFileName += vms.OopDesc.Sizeof
		if vms.Klass.Name != ^uint(0) {
			vms.Klass.Name += vms.OopDesc.Sizeof
		}
		vms.ConstantPool.SourceFileNameIndex = 0
		vms.InstanceKlass.SourceFileNameIndex = 0
	}

	// JDK-8: Only single CodeCache Heap, some CodeBlob and Nmethod changes
	if vms.CodeCache.Heap != ^libpf.Address(0) {
		// Validate values that can be missing, fixup CompiledMethod offsets
		vms.CodeCache.Heaps = 0
		vms.CodeCache.HighBound = 0
		vms.CodeCache.LowBound = 0
		vms.CompiledMethod.Sizeof = vms.Nmethod.Sizeof
		vms.CompiledMethod.DeoptHandlerBegin = vms.Nmethod.DeoptimizeOffset
		vms.CompiledMethod.Method = vms.Nmethod.Method
		vms.CompiledMethod.ScopesDataBegin = 0
	} else {
		// Reset the compatibility symbols not needed
		vms.CodeCache.Heap = 0
		vms.Nmethod.Method = 0
		vms.Nmethod.DeoptimizeOffset = 0
		vms.Nmethod.ScopesDataOffset = 0
	}

	// JDK12+: Use Symbol.Length_and_refcount for Symbol.Length
	if vms.Symbol.LengthAndRefcount != ^uint(0) {
		// The symbol _length was merged and renamed to _symbol_length_and_refcount.
		// Calculate the _length offset from it.
		vms.Symbol.Length = vms.Symbol.LengthAndRefcount + 2
	} else {
		// Reset the non-used symbols so the check below does not fail
		vms.Symbol.LengthAndRefcount = 0
	}

	// JDK16: use GenericGrowableArray as in JDK9-15 case
	if vms.GrowableArrayBase.Len != ^uint(0) {
		vms.GenericGrowableArray.Len = vms.GrowableArrayBase.Len
	} else {
		// Reset the non-used symbols so the check below does not fail
		vms.GrowableArrayBase.Len = 0
	}

	// JDK20+: UNSIGNED5 encoding change (since 20.0.15)
	// https://github.com/openjdk/jdk20u/commit/8d3399bf5f354931b0c62d2ed8095e554be71680
	if vmd.version >= 0x1400000f {
		vmd.unsigned5X = 1
	}

	// Check that all symbols got loaded from JVM introspection data
	err := forEachItem("", reflect.ValueOf(&vmd.vmStructs).Elem(),
		func(item reflect.Value, name string) error {
			switch item.Kind() {
			case reflect.Uint, reflect.Uint64:
				if item.Uint() != ^uint64(0) {
					return nil
				}
			case reflect.Uint32:
				if item.Uint() != uint64(^uint32(0)) {
					return nil
				}
			}
			return fmt.Errorf("JVM symbol '%v' not found", name)
		})
	if err != nil {
		vmd.err = err
		return vmd, nil
	}

	if vms.Symbol.Sizeof > 32 {
		// Additional sanity for Symbol.Sizeof which normally is
		// just 8 byte or so. The getSymbol() hard codes the first read
		// as 128 bytes and it needs to be more than this.
		vmd.err = fmt.Errorf("JVM Symbol.Sizeof value %d", vms.Symbol.Sizeof)
		return vmd, nil
	}

	// Verify that all struct fields are within limits
	structs := reflect.ValueOf(&vmd.vmStructs).Elem()
	for i := 0; i < structs.NumField(); i++ {
		klass := structs.Field(i)
		sizeOf := klass.FieldByName("Sizeof")
		if !sizeOf.IsValid() {
			continue
		}
		maxOffset := sizeOf.Uint()
		for j := 0; j < klass.NumField(); j++ {
			field := klass.Field(j)
			if field.Kind() == reflect.Map {
				continue
			}

			if field.Uint() > maxOffset {
				vmd.err = fmt.Errorf("%s.%s offset %v is larger than class size %v",
					structs.Type().Field(i).Name,
					klass.Type().Field(j).Name,
					field.Uint(), maxOffset)
				return vmd, nil
			}
		}
	}

	return vmd, nil
}

// locateJvmciVMStructs attempts to heuristically locate the JVMCI VM structs by
// searching for references to the string `Klass_vtable_start_offset`. In all JVM
// versions >= 9.0, this corresponds to the first entry in the VM structs:
//
// nolint:lll
// https://github.com/openjdk/jdk/blob/jdk-9%2B181/hotspot/src/share/vm/jvmci/vmStructs_jvmci.cpp#L48
// https://github.com/openjdk/jdk/blob/jdk-22%2B10/src/hotspot/share/jvmci/vmStructs_jvmci.cpp#L49
func locateJvmciVMStructs(ef *pfelf.File) (libpf.Address, error) {
	const maxDataReadSize = 1 * 1024 * 1024   // seen in practice: 192 KiB
	const maxRodataReadSize = 4 * 1024 * 1024 // seen in practice: 753 KiB

	rodataSec := ef.Section(".rodata")
	if rodataSec == nil {
		return 0, errors.New("unable to find `.rodata` section")
	}

	rodata, err := rodataSec.Data(maxRodataReadSize)
	if err != nil {
		return 0, err
	}

	offs := bytes.Index(rodata, []byte("Klass_vtable_start_offset"))
	if offs == -1 {
		return 0, errors.New("unable to find string for heuristic")
	}

	ptr := rodataSec.Addr + uint64(offs)
	ptrEncoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptrEncoded, ptr)

	dataSec := ef.Section(".data")
	if dataSec == nil {
		return 0, errors.New("unable to find `.data` section")
	}

	data, err := dataSec.Data(maxDataReadSize)
	if err != nil {
		return 0, err
	}

	offs = bytes.Index(data, ptrEncoded)
	if offs == -1 {
		return 0, errors.New("unable to find string pointer")
	}

	// 8 in the expression below is what we'd usually read from
	// gHotSpotVMStructEntryFieldNameOffset. This value unfortunately lives in
	// BSS, so we have no choice but to hard-code it. Fortunately enough this
	// offset hasn't changed since at least JDK 9.
	return libpf.Address(dataSec.Addr + uint64(offs) - 8), nil
}

// Loader is the main function for ProcessManager to recognize and hook the HotSpot
// libjvm for enabling JVM unwinding and symbolization.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !libjvmRegex.MatchString(info.FileName()) {
		return nil, nil
	}

	log.Debugf("HotSpot inspecting %v", info.FileName())

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	d := &hotspotData{}
	err = d.structPtrs.resolveSymbols(ef,
		[]string{
			"gHotSpotVMStructs",
			"gHotSpotVMStructEntryArrayStride",
			"gHotSpotVMStructEntryTypeNameOffset",
			"gHotSpotVMStructEntryFieldNameOffset",
			"gHotSpotVMStructEntryOffsetOffset",
			"gHotSpotVMStructEntryAddressOffset",
		})
	if err != nil {
		return nil, err
	}

	err = d.typePtrs.resolveSymbols(ef,
		[]string{
			"gHotSpotVMTypes",
			"gHotSpotVMTypeEntryArrayStride",
			"gHotSpotVMTypeEntryTypeNameOffset",
			"",
			"gHotSpotVMTypeEntrySizeOffset",
			"",
		})
	if err != nil {
		return nil, err
	}

	if ptr, err := locateJvmciVMStructs(ef); err == nil {
		// Everything except for the base pointer is identical.
		d.jvmciStructPtrs = d.structPtrs
		d.jvmciStructPtrs.base = ptr
		d.jvmciStructPtrs.skipBaseDref = true
	} else {
		log.Warnf("%s: unable to read JVMCI VM structs: %v", info.FileName(), err)
	}

	return d, nil
}
