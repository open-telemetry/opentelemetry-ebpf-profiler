// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// iseqCacheSize is the LRU size for caching Ruby instruction sequences for an interpreter.
	// This should reflect the number of hot functions that are seen often in a trace.
	iseqCacheSize = 1024
	// addrToStringSize is the LRU size for caching Ruby VM addresses to Ruby strings.
	addrToStringSize = 1024

	// rubyInsnInfoSizeLimit defines the limit up to which we will allocate memory for the
	// binary search algorithm to get the line number.
	rubyInsnInfoSizeLimit = 1 * 1024 * 1024
)

//nolint:lll
const (
	//RUBY_T_CLASS
	rubyTClass = 0x2
	//https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L114

	//RUBY_T_MODULE
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L115C5-L115C74
	rubyTModule = 0x3

	//RUBY_T_ICLASS
	//https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L138
	rubyTIClass = 0x1c

	// RUBY_T_STRING
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L117
	rubyTString = 0x5

	// RUBY_T_ARRAY
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L119
	rubyTArray = 0x7

	// RUBY_T_MASK
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L142
	rubyTMask = 0x1f

	// RSTRING_NOEMBED
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L978
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L855
	// 1 << 13
	rstringNoEmbed = 8192

	// RARRAY_EMBED_FLAG
	rarrayEmbed = 8192

	// PATHOBJ_REALPATH
	pathObjRealPathIdx = 1

	// ISEQ_TYPE_METHOD
	// https://github.com/ruby/ruby/blob/v3_4_5/vm_core.h#L380
	iseqTypeMethod = 1
)

const (
	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L158
	RUBY_FL_USHIFT = 12

	RUBY_FL_USER0 = 1 << (RUBY_FL_USHIFT + 0)
	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L323-L324
	RUBY_FL_USER1 = 1 << (RUBY_FL_USHIFT + 1)

	// Used for computing embed array flag
	RUBY_FL_USER3 = 1 << (RUBY_FL_USHIFT + 3)
	RUBY_FL_USER4 = 1 << (RUBY_FL_USHIFT + 4)
	RUBY_FL_USER5 = 1 << (RUBY_FL_USHIFT + 5)
	RUBY_FL_USER6 = 1 << (RUBY_FL_USHIFT + 6)
	RUBY_FL_USER7 = 1 << (RUBY_FL_USHIFT + 7)
	RUBY_FL_USER8 = 1 << (RUBY_FL_USHIFT + 8)
	RUBY_FL_USER9 = 1 << (RUBY_FL_USHIFT + 9)

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L102
	RARRAY_EMBED_FLAG = RUBY_FL_USER1

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L114-L115
	RARRAY_EMBED_LEN_MASK = RUBY_FL_USER9 | RUBY_FL_USER8 | RUBY_FL_USER7 | RUBY_FL_USER6 |
		RUBY_FL_USER5 | RUBY_FL_USER4 | RUBY_FL_USER3

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L122-L125
	RARRAY_EMBED_LEN_SHIFT = RUBY_FL_USHIFT + 3
)

var (
	// regex to identify the Ruby interpreter executable
	rubyRegex = regexp.MustCompile(`^(?:.*/)?libruby(?:-.*)?\.so\.(\d)\.(\d)\.(\d)$`)
	// regex to extract a version from a string
	rubyVersionRegex = regexp.MustCompile(`^(\d)\.(\d)\.(\d)$`)

	rubyProcessDied = libpf.Intern("PROCESS_DIED")
	rubyDeadFile    = libpf.Intern("<dead>")

	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &rubyData{}
	_ interpreter.Instance = &rubyInstance{}
)

//nolint:lll
type rubyData struct {
	// currentCtxPtr is the `ruby_current_execution_context_ptr` symbol value which is needed by the
	// eBPF program to build ruby backtraces.
	currentCtxPtr libpf.Address

	// Address to the ruby_current_ec variable in TLS, as an offset from tpbase
	currentEcTpBaseTlsOffset libpf.Address

	// Address to global symbols, for id to string mappings
	globalSymbolsAddr libpf.Address
	// version of the currently used Ruby interpreter.
	// major*0x10000 + minor*0x100 + release (e.g. 3.0.1 -> 0x30001)
	version uint32

	// this is compiled into ruby (id.h.tmpl) as a template and needed for symbolizing
	// c function frames
	// get this with `print (int)tLAST_OP_ID` in gdb
	lastOpId uint64

	// Flag for detecting singletons, can vary by version
	rubyFlSingleton libpf.Address

	// Is it possible to read the classpath
	hasClassPath bool

	// Is it possible to read the global symbol table (to symbolize cfuncs)
	hasGlobalSymbols bool

	// vmStructs reflects the Ruby internal names and offsets of named fields.
	vmStructs struct {
		// rb_execution_context_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L843
		execution_context_struct struct {
			vm_stack, vm_stack_size, cfp uint8
		}

		// rb_control_frame_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L760
		control_frame_struct struct {
			pc, iseq, ep                 uint8
			size_of_control_frame_struct uint8
		}

		// rb_iseq_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L456
		iseq_struct struct {
			body uint8
		}

		// rb_iseq_constant_body
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L311
		iseq_constant_body struct {
			iseq_type, encoded, size, location, insn_info_body, insn_info_size, succ_index_table uint8
			local_iseq, size_of_iseq_constant_body                                               uint16
		}

		// rb_iseq_location_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L272
		iseq_location_struct struct {
			pathobj, base_label, label uint8
		}

		// succ_index_table_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3420
		succ_index_table_struct struct {
			small_block_ranks, block_bits, succ_part, succ_dict_block uint8
			size_of_succ_dict_block                                   uint8
		}

		// iseq_insn_info_entry
		// https://github.com/ruby/ruby/blob/4e0a512972cdcbfcd5279f1a2a81ba342ed75b6e/iseq.h#L212
		iseq_insn_info_entry struct {
			position, line_no                                               uint8
			size_of_position, size_of_line_no, size_of_iseq_insn_info_entry uint8
		}

		// RString
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L988
		// https://github.com/ruby/ruby/blob/86ac17efde6cf98903513cac2538b15fc4ac80b2/include/ruby/internal/core/rstring.h#L196
		rstring_struct struct {
			// NOTE: starting with Ruby 3.1 the `as.ary` field is now `as.embed.ary`
			as_heap_ptr, as_ary uint8
		}

		// RArray
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L1048
		rarray_struct struct {
			as_heap_ptr, as_ary uint8
		}

		// size_of_immediate_table holds the size of the macro IMMEDIATE_TABLE_SIZE as defined in
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3418
		size_of_immediate_table uint8

		// size_of_value holds the size of the macro VALUE as defined in
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L1136
		size_of_value uint8

		// rb_ractor_struct
		// https://github.com/ruby/ruby/blob/5ce0d2aa354eb996cb3ca9bb944f880ff6acfd57/ractor_core.h#L82
		rb_ractor_struct struct {
			running_ec uint16
		}

		// TODO add links to the structs
		// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/method.h#L63-L69
		rb_method_entry_struct struct {
			flags, defined_class, def, owner uint8
		}

		rclass_and_rb_classext_t struct {
			classext uint8
		}

		rb_classext_struct struct {
			classpath, as_singleton_class_attached_object uint8
		}

		rb_method_definition_struct struct {
			method_type, body, original_id uint8
		}

		rb_method_iseq_struct struct {
			iseqptr uint8
		}
	}
}

func rubyVersion(major, minor, release uint32) uint32 {
	return major*0x10000 + minor*0x100 + release
}

func (r *rubyData) String() string {
	ver := r.version
	return fmt.Sprintf("Ruby %d.%d.%d", (ver>>16)&0xff, (ver>>8)&0xff, ver&0xff)
}

func (r *rubyData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	var tlsOffset uint64
	if r.currentEcTpBaseTlsOffset != 0 {
		// Read TLS offset from the TLS descriptor.
		tlsOffset = rm.Uint64(bias + r.currentEcTpBaseTlsOffset + 8)
	}

	cdata := support.RubyProcInfo{
		Version: r.version,

		Current_ctx_ptr:              uint64(r.currentCtxPtr + bias),
		Current_ec_tpbase_tls_offset: tlsOffset,

		Vm_stack:      r.vmStructs.execution_context_struct.vm_stack,
		Vm_stack_size: r.vmStructs.execution_context_struct.vm_stack_size,
		Cfp:           r.vmStructs.execution_context_struct.cfp,

		Pc:                           r.vmStructs.control_frame_struct.pc,
		Iseq:                         r.vmStructs.control_frame_struct.iseq,
		Ep:                           r.vmStructs.control_frame_struct.ep,
		Size_of_control_frame_struct: r.vmStructs.control_frame_struct.size_of_control_frame_struct,

		Body:           r.vmStructs.iseq_struct.body,
		Cme_method_def: r.vmStructs.rb_method_entry_struct.def,

		Size_of_value: r.vmStructs.size_of_value,

		Running_ec: r.vmStructs.rb_ractor_struct.running_ec,
	}

	if err := ebpf.UpdateProcData(libpf.Ruby, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	addrToString, err := freelru.New[libpf.Address, libpf.String](addrToStringSize,
		libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	log.Debugf("Bias is 0x%08x, global_symbols are 0x%08x, relocated xs 0x%08x", bias, r.globalSymbolsAddr, bias+r.globalSymbolsAddr)

	return &rubyInstance{
		r:                 r,
		rm:                rm,
		procInfo:          cdata,
		globalSymbolsAddr: r.globalSymbolsAddr + bias,
		addrToString:      addrToString,
		memPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 512)
				return &buf
			},
		},
	}, nil
}

func (r *rubyData) Unload(_ interpreter.EbpfHandler) {
}

// rubyIseq stores information extracted from a iseq_constant_body struct.
type rubyIseq struct {
	// sourceFileName is the extracted filename field
	sourceFileName libpf.String

	// label
	label libpf.String

	// base_label
	baseLabel libpf.String

	// methodName is the optional method name for this iseq
	// only present on CME-based iseq
	methodName libpf.String

	// line of code in source file for this instruction sequence
	line libpf.SourceLineno
}

type rubyInstance struct {
	interpreter.InstanceStubs

	// Ruby symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	r  *rubyData
	rm remotememory.RemoteMemory

	procInfo support.RubyProcInfo

	// globalSymbolsAddr is the offset of the global symbol table, for looking up ruby symbolic ids
	globalSymbolsAddr libpf.Address

	// addrToString maps an address to an extracted Ruby String from this address.
	addrToString *freelru.LRU[libpf.Address, libpf.String]

	// memPool provides pointers to byte arrays for efficient memory reuse.
	memPool sync.Pool

	// maxSize is the largest number we did see in the last reporting interval for size
	// in getRubyLineNo.
	maxSize atomic.Uint32
}

func (r *rubyInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.Ruby, pid)
}

// readRubyArrayDataPtr obtains the data pointer of a Ruby array (RArray).
//
// https://github.com/ruby/ruby/blob/95aff2146/include/ruby/internal/core/rarray.h#L87
func (r *rubyInstance) readRubyArrayDataPtr(addr libpf.Address) (libpf.Address, error) {
	flags := r.rm.Ptr(addr)
	if flags&rubyTMask != rubyTArray {
		return 0, fmt.Errorf("object at 0x%08X is not an array", addr)
	}

	vms := &r.r.vmStructs
	if flags&rarrayEmbed == rarrayEmbed {
		return addr + libpf.Address(vms.rarray_struct.as_ary), nil
	}

	p := r.rm.Ptr(addr + libpf.Address(vms.rarray_struct.as_heap_ptr))
	if p != 0 {
		return 0, fmt.Errorf("heap pointer of array at 0x%08X is 0", addr)
	}

	return addr, nil
}

// readPathObjRealPath reads the realpath field from a Ruby iseq pathobj.
//
// Path objects are represented as either a Ruby string (RString) or a
// Ruby arrays (RArray) with 2 entries. The first field contains a relative
// path, the second one an absolute one. All Ruby types start with an RBasic
// object that contains a type tag that we can use to determine what variant
// we're dealing with.
//
// https://github.com/ruby/ruby/blob/4e0a51297/iseq.c#L217
// https://github.com/ruby/ruby/blob/95aff2146/vm_core.h#L267
// https://github.com/ruby/ruby/blob/95aff2146/vm_core.h#L283
// https://github.com/ruby/ruby/blob/7127f39ba/vm_core.h#L321-L321
func (r *rubyInstance) readPathObjRealPath(addr libpf.Address) (string, error) {
	flags := r.rm.Ptr(addr)
	switch flags & rubyTMask {
	case rubyTString:
		return r.readRubyString(addr)
	case rubyTArray:
		vms := &r.r.vmStructs
		arrData, e := r.readRubyArrayDataPtr(addr)
		if e != nil {
			return "", e
		}

		// Read contiguous pointer values into a buffer to be more efficient
		dataBytes := make([]byte, 2*vms.size_of_value)
		if err := r.rm.Read(arrData, dataBytes); err != nil {
			return "", fmt.Errorf("failed to read array data bytes: %v", err)
		}

		var relTag, absTag uint64
		relVal := npsr.Ptr(dataBytes, 0)
		absVal := npsr.Ptr(dataBytes, uint(vms.size_of_value))
		if absVal != 0 {
			absTag = uint64(r.rm.Ptr(absVal)) & uint64(rubyTMask)
		}

		var candidate libpf.Address
		if absVal != 0 && absTag == uint64(rubyTString) {
			candidate = absVal
		} else if relVal != 0 {
			relTag = uint64(r.rm.Ptr(relVal)) & uint64(rubyTMask)
			if relTag == uint64(rubyTString) {
				candidate = relVal
			}
		} else {
			return "", fmt.Errorf("pathobj array has no string entries: relTag=0x%x absTag=0x%x", relTag, absTag)
		}

		return r.readRubyString(candidate)
	default:
		return "", fmt.Errorf("unexpected pathobj type tag: 0x%X", flags&rubyTMask)
	}
}

// readRubyString extracts a Ruby string from the given addr.
//
// 2.5.0: https://github.com/ruby/ruby/blob/4e0a51297/include/ruby/ruby.h#L1004
// 3.0.0: https://github.com/ruby/ruby/blob/48b94b791/include/ruby/internal/core/rstring.h#L73
func (r *rubyInstance) readRubyString(addr libpf.Address) (string, error) {
	flags := r.rm.Ptr(addr)
	if flags&rubyTMask != rubyTString {
		return "", fmt.Errorf("object at 0x%08X is not a string", addr)
	}

	var str string
	vms := &r.r.vmStructs
	if flags&rstringNoEmbed == rstringNoEmbed {
		str = r.rm.StringPtr(addr + libpf.Address(vms.rstring_struct.as_heap_ptr))
	} else {
		str = r.rm.String(addr + libpf.Address(vms.rstring_struct.as_ary))
	}

	r.addrToString.Add(addr, libpf.Intern(str))
	return str, nil
}

type StringReader = func(address libpf.Address) (string, error)

// getStringCached retrieves a string from cache or reads and inserts it if it's missing.
func (r *rubyInstance) getStringCached(addr libpf.Address, reader StringReader) (
	libpf.String, error,
) {
	if value, ok := r.addrToString.Get(addr); ok {
		return value, nil
	}

	str, err := reader(addr)
	if err != nil {
		return libpf.NullString, err
	}
	if !util.IsValidString(str) {
		log.Debugf("Extracted invalid string from Ruby at 0x%x, len=%d, bytes=%x",
			addr, len(str), []byte(str))
		return libpf.NullString, fmt.Errorf("extracted invalid Ruby string from address 0x%x", addr)
	}

	val := libpf.Intern(str)
	r.addrToString.Add(addr, val)
	return val, err
}

// rubyPopcount64 is a helper macro.
// Ruby makes use of __builtin_popcount intrinsics. These builtin intrinsics are not available
// here so we use the equivalent function of the Go standard library.
// https://github.com/ruby/ruby/blob/48b94b791997881929c739c64f95ac30f3fd0bb9/internal/bits.h#L408
func rubyPopcount64(in uint64) uint32 {
	return uint32(bits.OnesCount64(in))
}

// smallBlockRankGet is a helper macro.
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3432
func smallBlockRankGet(v uint64, i uint32) uint32 {
	if i == 0 {
		return 0
	}
	return uint32((v >> ((i - 1) * 9))) & 0x1ff
}

// immBlockRankGet is a helper macro.
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3430
func immBlockRankGet(v uint64, i uint32) uint32 {
	tmp := v >> (i * 7)
	return uint32(tmp) & 0x7f
}

// getObsoleteRubyLineNo implements a binary search algorithm to get the line number for a position.
//
// Implementation according to Ruby:
// https://github.com/ruby/ruby/blob/4e0a512972cdcbfcd5279f1a2a81ba342ed75b6e/iseq.c#L1254-L1295
func (r *rubyInstance) getObsoleteRubyLineNo(iseqBody libpf.Address,
	pos, size uint32,
) (uint32, error) {
	vms := &r.r.vmStructs
	sizeOfEntry := uint32(vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry)

	ptr := r.rm.Ptr(iseqBody + libpf.Address(vms.iseq_constant_body.insn_info_body))
	syncPoolData := r.memPool.Get().(*[]byte)
	if syncPoolData == nil {
		return 0, errors.New("failed to get memory from sync pool")
	}
	if uint32(len(*syncPoolData)) < size*sizeOfEntry {
		// make sure the data we want to write into blob fits in
		*syncPoolData = make([]byte, size*sizeOfEntry)
	}
	defer func() {
		// Reset memory and return it for reuse.
		for i := uint32(0); i < size*sizeOfEntry; i++ {
			(*syncPoolData)[i] = 0x0
		}
		r.memPool.Put(syncPoolData)
	}()
	blob := (*syncPoolData)[:size*sizeOfEntry]

	// Read the table with multiple iseq_insn_info_entry entries only once for the binary search.
	if err := r.rm.Read(ptr, blob); err != nil {
		return 0, fmt.Errorf("failed to read line table for binary search: %v", err)
	}

	var blobPos uint32
	var entryPos, entryLine uint32
	right := size - 1
	left := uint32(1)

	posOffset := uint32(vms.iseq_insn_info_entry.position)
	posSize := uint32(vms.iseq_insn_info_entry.size_of_position)
	lineNoOffset := uint32(vms.iseq_insn_info_entry.line_no)
	lineNoSize := uint32(vms.iseq_insn_info_entry.size_of_line_no)

	for left <= right {
		index := left + (right-left)/2

		blobPos = index * sizeOfEntry

		entryPos = binary.LittleEndian.Uint32(
			blob[blobPos+posOffset : blobPos+posOffset+posSize])
		entryLine = binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize])

		if entryPos == pos {
			return entryLine, nil
		}

		if entryPos < pos {
			left = index + 1
			continue
		}
		right = index - 1
	}

	if left >= size {
		blobPos = (size - 1) * sizeOfEntry
		return binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
	}

	blobPos = left * sizeOfEntry
	entryPos = binary.LittleEndian.Uint32(blob[blobPos+posOffset : blobPos+posOffset+posSize])

	if entryPos > pos {
		blobPos = (left - 1) * sizeOfEntry
		return binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
	}
	return binary.LittleEndian.Uint32(
		blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
}

// getRubyLineNo extracts the line number information from the given instruction sequence body and
// Ruby VM program counter.
// Starting with Ruby version 2.6.0 [0] Ruby no longer stores the information about the line number
// in a struct field but encodes them in a succinct data structure [1].
// For the lookup of the line number in this data structure getRubyLineNo follows the naming and
// implementation of the Ruby internal function succ_index_lookup [2].
//
// [0] https://github.com/ruby/ruby/commit/83262f24896abeaf1977c8837cbefb1b27040bef
// [1] https://en.wikipedia.org/wiki/Succinct_data_structure
// [2] https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3500-L3517
func (r *rubyInstance) getRubyLineNo(iseqBody libpf.Address, pc uint64) (uint32, error) {
	vms := &r.r.vmStructs

	// Read the struct iseq_constant_body only once.
	blob := make([]byte, vms.iseq_constant_body.size_of_iseq_constant_body)
	if err := r.rm.Read(iseqBody, blob); err != nil {
		return 0, fmt.Errorf("failed to read iseq_constant_body: %v", err)
	}

	offsetEncoded := vms.iseq_constant_body.encoded
	iseqEncoded := binary.LittleEndian.Uint64(blob[offsetEncoded : offsetEncoded+8])

	offsetSize := vms.iseq_constant_body.insn_info_size
	size := binary.LittleEndian.Uint32(blob[offsetSize : offsetSize+4])

	// For our better understanding and future improvement we track the maximum value we get for
	// size and report it.
	util.AtomicUpdateMaxUint32(&r.maxSize, size)

	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L1678
	if size == 0 {
		return 0, errors.New("failed to read size")
	}
	if size == 1 {
		offsetBody := vms.iseq_constant_body.insn_info_body
		lineNo := binary.LittleEndian.Uint32(blob[offsetBody : offsetBody+4])
		return lineNo, nil
	}
	if size > rubyInsnInfoSizeLimit {
		// When reading the value for size we don't have a way to validate this returned
		// value. To make sure we don't accept any arbitrary number we set here a limit of
		// 1MB.
		// Returning 0 here is not the correct line number at this point. But we let the
		// rest of the symbolization process unwind the frame and get the file name. This
		// way we can provide partial results.
		return 0, nil
	}

	// To get the line number iseq_encoded is subtracted from pc. This result also represents the
	// size of the current instruction sequence. If the calculated size of the instruction sequence
	// is greater than the value in iseq_encoded we don't report this pc to user space.
	//
	//nolint:lll
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L47-L48
	pos := (pc - iseqEncoded) / uint64(vms.size_of_value)
	if pos != 0 {
		pos--
	}

	// Ruby 2.6 changed the way of storing line numbers with [0]. As we still want to get
	// the line number information for older Ruby versions, we have this special
	// handling here.
	//
	// [0] https://github.com/ruby/ruby/commit/83262f24896abeaf1977c8837cbefb1b27040bef
	if r.r.version < 0x20600 {
		return r.getObsoleteRubyLineNo(iseqBody, uint32(pos), size)
	}

	offsetSuccTable := vms.iseq_constant_body.succ_index_table
	succIndexTable := binary.LittleEndian.Uint64(blob[offsetSuccTable : offsetSuccTable+8])

	if succIndexTable == 0 {
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L1686
		return 0, errors.New("failed to get table with line information")
	}

	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3500-L3517
	var tableIndex uint32
	if pos < uint64(vms.size_of_immediate_table) {
		i := int(pos / 9)
		j := int(pos % 9)
		immPart := r.rm.Uint64(libpf.Address(succIndexTable) +
			libpf.Address(i*int(vms.size_of_value)))
		if immPart == 0 {
			return 0, errors.New("failed to read immPart")
		}
		tableIndex = immBlockRankGet(immPart, uint32(j))
	} else {
		blockIndex := uint32((pos - uint64(vms.size_of_immediate_table)) / 512)
		blockOffset := libpf.Address(blockIndex *
			uint32(vms.succ_index_table_struct.size_of_succ_dict_block))

		rank := r.rm.Uint32(libpf.Address(succIndexTable) +
			libpf.Address(vms.succ_index_table_struct.succ_part) + blockOffset)
		if rank == 0 {
			return 0, errors.New("failed to read rank")
		}

		blockBitIndex := uint32((pos - uint64(vms.size_of_immediate_table)) % 512)
		smallBlockIndex := blockBitIndex / 64
		smallBlockOffset := libpf.Address(smallBlockIndex * uint32(vms.size_of_value))

		smallBlockRanks := r.rm.Uint64(libpf.Address(succIndexTable) + blockOffset +
			libpf.Address(vms.succ_index_table_struct.succ_part+
				vms.succ_index_table_struct.small_block_ranks))
		if smallBlockRanks == 0 {
			return 0, errors.New("failed to read smallBlockRanks")
		}

		smallBlockPopcount := smallBlockRankGet(smallBlockRanks, smallBlockIndex)

		blockBits := r.rm.Uint64(libpf.Address(succIndexTable) + blockOffset +
			libpf.Address(vms.succ_index_table_struct.succ_part+
				vms.succ_index_table_struct.block_bits) + smallBlockOffset)
		if blockBits == 0 {
			return 0, errors.New("failed to read blockBits")
		}
		popCnt := rubyPopcount64((blockBits << (63 - blockBitIndex%64)))

		tableIndex = rank + smallBlockPopcount + popCnt
	}
	tableIndex--

	offsetBody := vms.iseq_constant_body.insn_info_body
	lineNoAddr := binary.LittleEndian.Uint64(blob[offsetBody : offsetBody+8])
	if lineNoAddr == 0 {
		return 0, errors.New("failed to read lineNoAddr")
	}

	lineNo := r.rm.Uint32(libpf.Address(lineNoAddr) +
		libpf.Address(tableIndex*uint32(vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry)))
	if lineNo == 0 {
		return 0, errors.New("failed to read lineNo")
	}
	return lineNo, nil
}

func (r *rubyInstance) readClassName(classAddr libpf.Address) (libpf.String, bool, error) {
	var classPath libpf.String
	var classpathPtr libpf.Address
	var singleton bool
	var err error

	classFlags := r.rm.Ptr(classAddr)
	classMask := classFlags & rubyTMask

	// TODO clean this up more
	classpathPtr = r.rm.Ptr(classAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))
	if classMask == rubyTIClass {
		//https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1931-L1933

		// Get the 'klass'
		// struct RBasic {
		//    VALUE                      flags;                /*     0     8 */
		//    const VALUE                klass;                /*     8     8 */
		// ...
		RBASIC_KCLASS_OFFSET := libpf.Address(8) // TODO readthis from `RBasic` struct and store on vmstructs

		if klassAddr := r.rm.Ptr(classAddr + RBASIC_KCLASS_OFFSET); klassAddr != 0 {
			log.Debugf("Using klass for iclass type")
			classpathPtr = r.rm.Ptr(klassAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))
		}
	} else if classFlags&r.r.rubyFlSingleton != 0 {
		// Should also check if it is a singleton
		// https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1934-L1937
		// https://github.com/ruby/ruby/blob/b627532/internal/class.h#L528

		singleton = true
		singletonObject := r.rm.Ptr(classAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.as_singleton_class_attached_object))
		classpathPtr = r.rm.Ptr(singletonObject + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))

		// TODO handle anonymous classes
		// If it is neither a class nor a module, we should handle what i guess is an anonymous class?
		// https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1936-L1937 (see rb_class2name)

		// #define RCLASS_EXT_PRIME(c) (&((struct RClass_and_rb_classext_t*)(c))->classext)
		// #define RCLASS_ATTACHED_OBJECT(c) (RCLASS_EXT_PRIME(c)->as.singleton_class.attached_object)
	}

	// TODO Document we are only doing the "happy path" where there is a classpath, and not
	// handling the anonymous case or weird module cases yet.
	if classpathPtr != 0 {
		classPath, err = r.getStringCached(classpathPtr, r.readRubyString)
		if err != nil {
			return libpf.NullString, singleton, fmt.Errorf("unable to read classpath string %x %v", classpathPtr, err)
		}
	}

	return classPath, singleton, nil
}

// Aims to mimic the logic of id2str, which ultimately calls this
// https://github.com/ruby/ruby/blob/v3_4_5/symbol.c#L450-L499
func (r *rubyInstance) id2str(originalId uint64) (libpf.String, error) {
	var symbolName libpf.String
	var err error

	vms := &r.r.vmStructs

	// RUBY_ID_SCOPE_SHIFT = 4
	// https://github.com/ruby/ruby/blob/797a4115bbb249c4f5f11e1b4bacba7781c68cee/template/id.h.tmpl#L30
	RUBY_ID_SCOPE_SHIFT := 4

	// TODO handle differences post 3.4.6:
	//prior to 3.4.6:
	// typedef struct {
	//     rb_id_serial_t last_id; (uint32_t, 4 bytes)
	//     st_table *str_sym; (pointer, so 8 bytes?)
	//     VALUE ids; (4 + 8 = 12 offset)
	//     VALUE dsymbol_fstr_hash;
	// } rb_symbols_t;
	//after 3.4.6:
	// typedef struct {
	//     rb_atomic_t next_id; (int, probably 4 bytes)
	//     VALUE sym_set; (size of 8)
	//
	//     VALUE ids; (4 + 8 = 12 offset)
	// } rb_symbols_t;

	IDS_OFFSET := 16 // rb_id_serial_t probably gets padded to be word-aligned

	serial := originalId
	if originalId > r.r.lastOpId {
		serial = originalId >> RUBY_ID_SCOPE_SHIFT
	}

	lastId := r.rm.Uint32(r.globalSymbolsAddr)

	if serial > uint64(lastId) {
		return libpf.NullString, fmt.Errorf("invalid serial %d, greater than last id %d", serial, lastId)
	}

	ids := r.rm.Ptr(r.globalSymbolsAddr + libpf.Address(IDS_OFFSET))

	// https://github.com/ruby/ruby/blob/v3_4_5/symbol.c#L77
	ID_ENTRY_UNIT := uint64(512)

	idx := serial / ID_ENTRY_UNIT

	// string2cstring
	flags := r.rm.Ptr(ids)

	var idsPtr libpf.Address
	var idsLen uint64

	// Handle embedded arrays
	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L297-L307
	if (flags & RARRAY_EMBED_FLAG) > 0 {
		log.Debugf("Handling embedded array with shift")
		// It is embedded, so just get the offset of as.ary
		idsPtr = r.rm.Ptr(ids + libpf.Address(vms.rarray_struct.as_ary))

		// Get the length from the flags
		// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L240-L242
		idsLen = uint64((flags & RARRAY_EMBED_LEN_MASK) >> RARRAY_EMBED_LEN_SHIFT)
	} else {
		idsPtr = r.rm.Ptr(ids + libpf.Address(vms.rarray_struct.as_heap_ptr))
		// NOTE assuming that len and ary are at the same location in union, this might not be valid
		// We may want to add these as separate struct fields in case this data structure changes
		idsLen = r.rm.Uint64(ids + libpf.Address(vms.rarray_struct.as_ary))
	}

	if idx > idsLen {
		return libpf.NullString, fmt.Errorf("invalid idx %d, number of ids %d", idx, idsLen)
	}

	array := r.rm.Ptr(idsPtr + libpf.Address(idx*8)) // TODO don't hardcode 8 here, we just need the word size though
	arrayPtr := r.rm.Ptr(array + libpf.Address(vms.rarray_struct.as_heap_ptr))

	flags = r.rm.Ptr(array)
	if (flags & RARRAY_EMBED_FLAG) > 0 {
		log.Debugf("Handling embedded array (2 levels) with shift")
		arrayPtr = r.rm.Ptr(array + libpf.Address(vms.rarray_struct.as_ary))
	}
	offset := (serial % 512) * 2
	stringPtr := r.rm.Ptr(arrayPtr + libpf.Address(offset*8))

	symbolName, err = r.getStringCached(stringPtr, r.readRubyString)
	if err != nil {
		log.Errorf("Unable to read string %v", err)
	}

	return symbolName, err
}

func (r *rubyInstance) PtrCheck(addr libpf.Address) (libpf.Address, error) {
	var buf [8]byte
	if err := r.rm.Read(addr, buf[:]); err != nil {
		return 0, err
	}
	return libpf.Address(binary.LittleEndian.Uint64(buf[:])) - r.rm.Bias, nil
}

// Reconstructing (expanding back to 32 bits with 0xF fill)
func unpackEnvFlags(packed uint16) uint32 {
	// Extract the saved bytes
	highByte := uint32((packed >> 8) & 0xFF) // Gets 0x22
	lowByte := uint32(packed & 0xFF)         // Gets 0x02

	// Reconstruct with pattern: 0xHH HH F LL F
	// Where HH = highByte (repeated), LL = lowByte
	reconstructed := (highByte << 24) | // 0x22000000
		(highByte << 16) | // 0x00220000 (repeat high)
		(0xF << 12) | // 0x0000F000
		(lowByte << 4) | // 0x00000020
		0xF // 0x0000000F

	return reconstructed // 0x2222F02F
}

func (r *rubyInstance) readIseqBody(iseqBody, pc libpf.Address, frameAddrType uint8, frameFlags uint32) (*rubyIseq, error) {
	vms := &r.r.vmStructs
	if _, err := r.PtrCheck(iseqBody); err != nil && errors.Is(err, syscall.ESRCH) {
		return nil, err
	}
	lineNo, err := r.getRubyLineNo(iseqBody, uint64(pc))
	if err != nil {
		lineNo = 0
		log.Warnf("RubySymbolizer: Failed to get line number (%d) %v", frameAddrType, err)
	}

	// TODO PtrCheck for all of these reads, if they were supposed to succeed
	// but the process died, mark that.
	// For the string reads, on error, check the pointer is valid in case it died
	sourceFileNamePtr := r.rm.Ptr(iseqBody +
		libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.pathobj))
	sourceFileName, err := r.getStringCached(sourceFileNamePtr, r.readPathObjRealPath)
	if err != nil {
		sourceFileName = libpf.Intern("UNKNOWN_FILE")
		log.Warnf("RubySymbolizer: Failed to get source file name %v", err)
	}

	iseqLabelPtr, err := r.PtrCheck(iseqBody +
		libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.label))
	if err != nil && errors.Is(err, syscall.ESRCH) {
		return nil, err
	}
	iseqLabel, err := r.getStringCached(iseqLabelPtr, r.readRubyString)
	if err != nil {
		//iseqLabel = libpf.Intern("UNKNOWN_LABEL")
		log.Warnf("RubySymbolizer: Failed to get source label (iseq@0x%08x) %d %08x, %v", iseqBody, frameAddrType, frameFlags, err)
		return &rubyIseq{}, err
	}

	iseqBaseLabelPtr, err := r.PtrCheck(iseqBody +
		libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.base_label))
	if err != nil && errors.Is(err, syscall.ESRCH) {
		return nil, err
	}
	iseqBaseLabel, err := r.getStringCached(iseqBaseLabelPtr, r.readRubyString)
	if err != nil {
		//iseqBaseLabel = libpf.Intern("UNKNOWN_LABEL")
		log.Warnf("RubySymbolizer: Failed to get source base label (iseq@0x%08x) %d %08x, %v", iseqBody, frameAddrType, frameFlags, err)
		return &rubyIseq{}, err
	}

	// Body used for for qualified method label is indirect, need to do: iseq body -> local iseq -> iseq body
	// https://github.com/ruby/ruby/blob/v3_4_5/vm_backtrace.c#L1943
	// https://github.com/ruby/ruby/blob/v3_4_5/iseq.c#L1426
	localIseqPtr, err := r.PtrCheck(iseqBody + libpf.Address(vms.iseq_constant_body.local_iseq))
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, err
		}
		log.Errorf("Unable to dereference local iseq: %v", err)
	}
	iseqLocalBody, err := r.PtrCheck(localIseqPtr + libpf.Address(vms.iseq_struct.body))
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, err
		}
		log.Errorf("Unable to dereference local iseq body: %v", err)
	}

	// Check iseq body type to see if it is a method
	// https://github.com/ruby/ruby/blob/v3_4_5/iseq.c#L1428-L1430
	iseqType := r.rm.Uint32(iseqLocalBody + libpf.Address(vms.iseq_constant_body.iseq_type))

	var methodName libpf.String
	if iseqType == iseqTypeMethod {
		methodNamePtr, err := r.PtrCheck(iseqLocalBody +
			libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.base_label))
		if err != nil && errors.Is(err, syscall.ESRCH) {
			return nil, err
		}
		methodName, err = r.getStringCached(methodNamePtr, r.readRubyString)
		if err != nil {
			//methodName = libpf.Intern(fmt.Sprintf("UNKNOWN_FUNCTION %d %08x", frameAddrType, frame.Extra))
			// TODO check if it is a block / block method before complaining here
			log.Warnf("Unable to find local method name on iseq method (%d) (iseq@0x%08x) %v", iseqType, iseqBody, err)
		}
	}

	return &rubyIseq{
		label:          iseqLabel,
		baseLabel:      iseqBaseLabel,
		methodName:     methodName,
		sourceFileName: sourceFileName,
		line:           libpf.SourceLineno(lineNo),
	}, nil
}

func (r *rubyInstance) Symbolize(frame *host.Frame, frames *libpf.Frames) error {
	if !frame.Type.IsInterpType(libpf.Ruby) {
		return interpreter.ErrMismatchInterpreterType
	}
	sfCounter := successfailurecounter.New(&r.successCount, &r.failCount)
	defer sfCounter.DefaultToFailure()

	var err error
	var iseqBody libpf.Address
	var classPath libpf.String
	var methodName libpf.String
	var fullLabel libpf.String
	var sourceFile libpf.String
	var sourceLine libpf.SourceLineno
	var singleton bool
	var cframe bool
	var cme bool

	vms := &r.r.vmStructs
	frameAddr := libpf.Address(frame.File & support.RubyAddrMask48Bit)
	frameAddrType := uint8(frame.File >> 48)
	pc := libpf.Address(frame.Lineno & support.RubyAddrMask48Bit)

	frameFlags := unpackEnvFlags(uint16(frame.Lineno >> 48))

	switch frameAddrType {
	case support.RubyFrameTypeCmeCfunc:
		cme = true
		cframe = true
		methodDefinition, err := r.PtrCheck(frameAddr + libpf.Address(vms.rb_method_entry_struct.def))
		if err != nil {
			return err
		}

		originalId := r.rm.Uint64(methodDefinition + libpf.Address(vms.rb_method_definition_struct.original_id))

		if r.r.hasGlobalSymbols {
			methodName, err = r.id2str(originalId)
			if err != nil {
				return err
			}
		} else {
			methodName = libpf.Intern("UNKNOWN CFUNC")
		}
	case support.RubyFrameTypeCmeIseq:
		cme = true

		methodDefinition, err := r.PtrCheck(frameAddr + libpf.Address(vms.rb_method_entry_struct.def))
		if err != nil {
			return fmt.Errorf("Unable to read method definition, CME (%08x) %v", frameAddr, err)
		}

		methodBody := r.rm.Ptr(methodDefinition + libpf.Address(vms.rb_method_definition_struct.body))
		if methodBody == 0 {
			return fmt.Errorf("unable to read method body for CME")
		}

		iseqBody = r.rm.Ptr(methodBody + libpf.Address(vms.rb_method_iseq_struct.iseqptr+vms.iseq_struct.body))

		if iseqBody == 0 {
			return fmt.Errorf("unable to read iseq body for CME")
		}

	case support.RubyFrameTypeIseq:
		iseqBody = libpf.Address(frameAddr)
	default:
		return fmt.Errorf("Unable to get CME or ISEQ from frame address")
	}

	if cme && r.r.hasClassPath {
		classDefinition := r.rm.Ptr(frameAddr + libpf.Address(vms.rb_method_entry_struct.defined_class))

		// TODO version gate this
		classPath, singleton, err = r.readClassName(classDefinition)
		if err != nil {
			log.Errorf("Failed to read class name for cme: %v", err)
		}
	}

	if err != nil {
		log.Errorf("Couldn't handle frame (%d) (%04x) 0x%08x (pc: 0x%08x) as %d frame %08x %v", frameAddrType, frameFlags, frameAddr, pc, frameAddrType, iseqBody, err)
		return err
	}

	// cframe get the method name from the global ID table
	// iseq-based calls from here share common logic to compute their full label
	// so we gather their requirements here
	if cframe {
		fullLabel = qualifiedMethodName(classPath, methodName, singleton)
		sourceFile = libpf.Intern("<cfunc>")
	} else {
		// The Ruby VM program counter that was extracted from the current call frame is embedded in
		// the Linenos field.
		iseq, err := r.readIseqBody(iseqBody, pc, frameAddrType, frameFlags)
		if err != nil {
			return err
		}
		sourceFile = iseq.sourceFileName
		sourceLine = iseq.line

		fullLabel = profileFrameFullLabel(classPath, iseq.label, iseq.baseLabel, iseq.methodName, singleton, cframe)

		if fullLabel == libpf.NullString {
			fullLabel = libpf.Intern(fmt.Sprintf("UNKNOWN_FUNCTION %d %08x", frameAddrType, frameFlags))
		}
	}
	frames.Append(&libpf.Frame{
		Type:         libpf.RubyFrame,
		FunctionName: fullLabel,
		SourceFile:   sourceFile,
		SourceLine:   sourceLine,
	})
	sfCounter.ReportSuccess()
	return nil
}

func qualifiedMethodName(classPath, methodName libpf.String, singleton bool) libpf.String {
	if methodName == libpf.NullString {
		return methodName
	}
	if classPath != libpf.NullString {
		joinChar := "#"
		if singleton {
			joinChar = "."
		}
		methodName = libpf.Intern(fmt.Sprintf("%s%s%s", classPath, joinChar, methodName))
	}

	return methodName
}

// TODO make some tests for profileFullLabelName to cover the various cases it needs
// to handle correctly
func profileFrameFullLabel(classPath, label, baseLabel, methodName libpf.String, singleton, cframe bool) libpf.String {
	qualified := qualifiedMethodName(classPath, methodName, singleton)

	if cframe {
		return qualified
	}

	if qualified == libpf.NullString || qualified == baseLabel {
		return label
	}

	labelLength := len(label.String())
	baseLabelLength := len(baseLabel.String())
	prefixLen := labelLength - baseLabelLength

	// Ensure prefixLen doesn't exceed label length (defensive programming)
	if prefixLen < 0 {
		prefixLen = 0
	}

	if prefixLen > labelLength {
		prefixLen = labelLength
	}

	profileLabel := label.String()[:prefixLen] + qualified.String()

	if len(profileLabel) == 0 {
		return libpf.NullString
	}

	// Get the prefix from label and concatenate with qualifiedMethodName
	return libpf.Intern(profileLabel)
}

func (r *rubyInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToStringStats := r.addrToString.ResetMetrics()

	return []metrics.Metric{
		{
			ID:    metrics.IDRubySymbolizationSuccess,
			Value: metrics.MetricValue(r.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDRubySymbolizationFailure,
			Value: metrics.MetricValue(r.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDRubyAddrToStringHit,
			Value: metrics.MetricValue(addrToStringStats.Hits),
		},
		{
			ID:    metrics.IDRubyAddrToStringMiss,
			Value: metrics.MetricValue(addrToStringStats.Misses),
		},
		{
			ID:    metrics.IDRubyAddrToStringAdd,
			Value: metrics.MetricValue(addrToStringStats.Inserts),
		},
		{
			ID:    metrics.IDRubyAddrToStringDel,
			Value: metrics.MetricValue(addrToStringStats.Removals),
		},
		{
			ID:    metrics.IDRubyMaxSize,
			Value: metrics.MetricValue(r.maxSize.Swap(0)),
		},
	}, nil
}

// determineRubyVersion looks for the symbol ruby_version and extracts version
// information from its value.
func determineRubyVersion(ef *pfelf.File) (uint32, error) {
	_, memory, err := ef.SymbolData("ruby_version", 64)
	if err != nil {
		return 0, fmt.Errorf("unable to read 'ruby_version': %v", err)
	}

	versionString := strings.TrimRight(pfunsafe.ToString(memory), "\x00")
	matches := rubyVersionRegex.FindStringSubmatch(versionString)
	if len(matches) < 3 {
		return 0, fmt.Errorf("failed to parse version string: '%s'", versionString)
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	release, _ := strconv.Atoi(matches[3])

	return rubyVersion(uint32(major), uint32(minor), uint32(release)), nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !rubyRegex.MatchString(info.FileName()) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	version, err := determineRubyVersion(ef)
	if err != nil {
		return nil, err
	}

	// Reason for lowest supported version:
	// - Ruby 2.5 is still commonly used at time of writing this code.
	//   https://www.jetbrains.com/lp/devecosystem-2020/ruby/
	// Reason for maximum supported version 3.5.x:
	// - this is currently the newest stable version
	minVer, maxVer := rubyVersion(2, 5, 0), rubyVersion(3, 6, 0)
	if version < minVer || version >= maxVer {
		return nil, fmt.Errorf("unsupported Ruby %d.%d.%d (need >= %d.%d.%d and <= %d.%d.%d)",
			(version>>16)&0xff, (version>>8)&0xff, version&0xff,
			(minVer>>16)&0xff, (minVer>>8)&0xff, minVer&0xff,
			(maxVer>>16)&0xff, (maxVer>>8)&0xff, maxVer&0xff)
	}

	log.Debugf("Ruby %d.%d.%d detected", (version>>16)&0xff, (version>>8)&0xff, version&0xff)

	// Before Ruby 2.5 the symbol ruby_current_thread was used for the current execution
	// context but got replaced in [0] with ruby_current_execution_context_ptr.
	// With [1] the Ruby internal execution model changed and the symbol
	// ruby_current_execution_context_ptr was removed. Therefore we need to lookup different
	// symbols depending on the version.
	// [0] https://github.com/ruby/ruby/commit/837fd5e494731d7d44786f29e7d6e8c27029806f
	// [1] https://github.com/ruby/ruby/commit/79df14c04b452411b9d17e26a398e491bca1a811
	currentCtxSymbol := libpf.SymbolName("ruby_single_main_ractor")
	if version < rubyVersion(3, 0, 0) {
		currentCtxSymbol = "ruby_current_execution_context_ptr"
	}

	var currentEcTpBaseTlsOffset libpf.Address
	var interpRanges []util.Range

	globalSymbolsName := libpf.SymbolName("ruby_global_symbols")
	if version < rubyVersion(2, 7, 0) {
		globalSymbolsName = libpf.SymbolName("global_symbols")
	}

	// rb_vm_exec is used to execute the Ruby frames in the Ruby VM and is called within
	// ruby_run_node  which is the main executor function since Ruby v1.9.0
	// https://github.com/ruby/ruby/blob/587e6800086764a1b7c959976acef33e230dccc2/main.c#L47
	interpSymbolName := libpf.SymbolName("rb_vm_exec")
	if version < rubyVersion(2, 6, 0) {
		interpSymbolName = libpf.SymbolName("ruby_exec_node")
	}

	rubyCurrentEcTlsSymbol := "ruby_current_ec"
	var currentEcSymbolAddress libpf.SymbolValue

	currentEcSymbolName := libpf.SymbolName(rubyCurrentEcTlsSymbol)

	log.Debugf("Ruby %d.%d.%d detected, looking for currentCtxPtr=%q, currentEcSymbol=%q",
		(version>>16)&0xff, (version>>8)&0xff, version&0xff, currentCtxSymbol, currentEcSymbolName)

	// Symbol discovery strategy:
	// - Ruby < 3.0.4: Uses currentCtxPtr (global/ractor-based execution context)
	// - Ruby >= 3.0.4: Uses currentEcSymbol (TLS-based execution context via ruby_current_ec)
	// When direct lookup fails, VisitSymbols scans all symbols as fallback.
	// eBPF selects the appropriate method based on version at runtime.
	currentCtxPtr, err := ef.LookupSymbolAddress(currentCtxSymbol)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", currentCtxSymbol, err)
	}

	interpRanges, err = info.GetSymbolAsRanges(interpSymbolName)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", interpSymbolName, err)
	}

	globalSymbolsAddr, err := ef.LookupSymbolAddress(globalSymbolsName)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", globalSymbolsName, err)
	}

	if err = ef.VisitSymbols(func(s libpf.Symbol) bool {
		if s.Name == currentEcSymbolName {
			currentEcSymbolAddress = s.Address
		}
		if s.Name == currentCtxSymbol {
			currentCtxPtr = s.Address
		}
		if s.Name == globalSymbolsName {
			globalSymbolsAddr = s.Address
		}
		if len(interpRanges) == 0 && s.Name == interpSymbolName {
			interpRanges = []util.Range{{
				Start: uint64(s.Address),
				End:   uint64(s.Address) + s.Size,
			}}
		}
		if len(interpRanges) > 0 && currentEcSymbolAddress != 0 && currentCtxPtr != 0 && globalSymbolsAddr != libpf.SymbolValueInvalid {
			return false
		}
		return true
	}); err != nil {
		log.Warnf("failed to visit symbols: %v", err)
	}

	// NOTE for ruby 3.3.0+, if ruby is stripped, we have no way of locating
	// ruby_current_ec TLS symbol.
	// We could potentially add a fallback for this in the future, but for now
	// only unstripped ruby is supported. Many distro supplied rubies are stripped.
	if err = ef.VisitTLSRelocations(func(r pfelf.ElfReloc, symName string) bool {
		if symName == rubyCurrentEcTlsSymbol ||
			libpf.SymbolValue(r.Addend) == currentEcSymbolAddress {
			currentEcTpBaseTlsOffset = libpf.Address(r.Off)
			return false
		}
		return true
	}); err != nil {
		log.Warnf("failed to locate TLS descriptor: %v", err)
	}

	log.Debugf("Discovered EC tls tpbase offset %x, fallback ctx %x, interp ranges: %v, global symbols: %x", currentEcTpBaseTlsOffset, currentCtxPtr, interpRanges, globalSymbolsAddr)

	rid := &rubyData{
		version:                  version,
		currentEcTpBaseTlsOffset: libpf.Address(currentEcTpBaseTlsOffset),
		currentCtxPtr:            libpf.Address(currentCtxPtr),
		globalSymbolsAddr:        libpf.Address(globalSymbolsAddr),
	}

	rid.hasGlobalSymbols = globalSymbolsAddr != 0

	vms := &rid.vmStructs
	switch {
	case version < rubyVersion(3, 3, 0):
		rid.hasClassPath = false
	case version < rubyVersion(3, 4, 0):
		rid.hasClassPath = true
		rid.rubyFlSingleton = libpf.Address(RUBY_FL_USER0)

		vms.rclass_and_rb_classext_t.classext = 32
		vms.rb_classext_struct.as_singleton_class_attached_object = 96
		vms.rb_classext_struct.classpath = 120
	default:
		rid.hasClassPath = true
		rid.rubyFlSingleton = libpf.Address(RUBY_FL_USER1)

		vms.rclass_and_rb_classext_t.classext = 32
		vms.rb_classext_struct.as_singleton_class_attached_object = 96
		vms.rb_classext_struct.classpath = 120
	}

	switch {
	case version < rubyVersion(2, 6, 0):
		rid.lastOpId = 166
	case version < rubyVersion(2, 7, 0):
		rid.lastOpId = 164
	case version < rubyVersion(3, 1, 0):
		rid.lastOpId = 168
	case version < rubyVersion(3, 4, 0):
		rid.lastOpId = 169
	case version < rubyVersion(3, 5, 0):
		rid.lastOpId = 170
	default:
		rid.lastOpId = 170
	}

	// Ruby does not provide introspection data, hard code the struct field offsets. Some
	// values can be fairly easily calculated from the struct definitions, but some are
	// looked up by using gdb and getting the field offset directly from debug data.
	vms.execution_context_struct.vm_stack = 0
	vms.execution_context_struct.vm_stack_size = 8
	vms.execution_context_struct.cfp = 16

	vms.control_frame_struct.pc = 0
	vms.control_frame_struct.iseq = 16
	vms.control_frame_struct.ep = 32
	switch {
	case version < rubyVersion(2, 6, 0):
		vms.control_frame_struct.size_of_control_frame_struct = 48
	case version < rubyVersion(3, 1, 0):
		// With Ruby 2.6 the field bp was added to rb_control_frame_t
		// https://github.com/ruby/ruby/commit/ed935aa5be0e5e6b8d53c3e7d76a9ce395dfa18b
		vms.control_frame_struct.size_of_control_frame_struct = 56
	case version < rubyVersion(3, 3, 0):
		// 3.1 adds new jit_return field at the end.
		// https://github.com/ruby/ruby/commit/9d8cc01b758f9385bd4c806f3daff9719e07faa0
		vms.control_frame_struct.size_of_control_frame_struct = 64
	default:
		// 3.3+ bp field was removed
		// https://github.com/ruby/ruby/commit/f302e725e10ae05e613e2c24cae0741f65f2db91
		vms.control_frame_struct.size_of_control_frame_struct = 56
	}
	vms.iseq_struct.body = 16

	vms.iseq_constant_body.iseq_type = 0
	vms.iseq_constant_body.size = 4
	vms.iseq_constant_body.encoded = 8
	vms.iseq_constant_body.location = 64
	vms.iseq_constant_body.local_iseq = 168
	switch {
	case version < rubyVersion(2, 6, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 200
		vms.iseq_constant_body.succ_index_table = 144
		vms.iseq_constant_body.local_iseq = 176
		vms.iseq_constant_body.size_of_iseq_constant_body = 288
	case version < rubyVersion(3, 2, 0):
		vms.iseq_constant_body.insn_info_body = 120
		vms.iseq_constant_body.insn_info_size = 136
		vms.iseq_constant_body.succ_index_table = 144
		vms.iseq_constant_body.local_iseq = 176
		vms.iseq_constant_body.size_of_iseq_constant_body = 312
	case version < rubyVersion(3, 3, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.local_iseq = 168
		vms.iseq_constant_body.size_of_iseq_constant_body = 320
	case version >= rubyVersion(3, 4, 0) && version < rubyVersion(3, 5, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.local_iseq = 168
		vms.iseq_constant_body.size_of_iseq_constant_body = 352
	default: // 3.3.x and 3.5.x have the same values
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.local_iseq = 168
		vms.iseq_constant_body.size_of_iseq_constant_body = 344
	}
	vms.iseq_location_struct.pathobj = 0
	vms.iseq_location_struct.base_label = 8
	vms.iseq_location_struct.label = 16

	switch {
	case version < rubyVersion(2, 6, 0):
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 4
		vms.iseq_insn_info_entry.line_no = 4
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 12
	case version < rubyVersion(3, 1, 0):
		// The position field was removed from this struct with
		// https://github.com/ruby/ruby/commit/295838e6eb1d063c64f7cde5bbbd13c7768908fd
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 0
		vms.iseq_insn_info_entry.line_no = 0
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 8
	default:
		// https://github.com/ruby/ruby/commit/0a36cab1b53646062026c3181117fad73802baf4
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 0
		vms.iseq_insn_info_entry.line_no = 0
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 12
	}
	if version < rubyVersion(3, 2, 0) {
		vms.rstring_struct.as_ary = 16
	} else {
		vms.rstring_struct.as_ary = 24
	}
	vms.rstring_struct.as_heap_ptr = 24

	vms.rarray_struct.as_ary = 16
	vms.rarray_struct.as_heap_ptr = 32

	vms.succ_index_table_struct.small_block_ranks = 8
	vms.succ_index_table_struct.block_bits = 16
	vms.succ_index_table_struct.succ_part = 48
	vms.succ_index_table_struct.size_of_succ_dict_block = 80
	vms.size_of_immediate_table = 54

	vms.size_of_value = 8

	vms.rb_method_entry_struct.flags = 0
	vms.rb_method_entry_struct.defined_class = 8
	vms.rb_method_entry_struct.def = 16
	vms.rb_method_entry_struct.owner = 32

	vms.rb_method_definition_struct.method_type = 0
	vms.rb_method_definition_struct.body = 8
	vms.rb_method_definition_struct.original_id = 32
	vms.rb_method_iseq_struct.iseqptr = 0

	if version >= rubyVersion(3, 0, 0) {
		if version >= rubyVersion(3, 3, 0) {
			if runtime.GOARCH == "amd64" {
				vms.rb_ractor_struct.running_ec = 0x180
			} else {
				vms.rb_ractor_struct.running_ec = 0x190
			}

		} else {
			if runtime.GOARCH == "amd64" {
				vms.rb_ractor_struct.running_ec = 0x208
			} else {
				vms.rb_ractor_struct.running_ec = 0x218
			}
		}
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindRuby, info.FileID(),
		interpRanges); err != nil {
		return nil, err
	}

	return rid, nil
}
