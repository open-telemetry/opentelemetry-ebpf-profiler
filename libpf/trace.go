// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"hash/maphash"
	"strconv"
	"unique"
	"unsafe"

	"github.com/zeebo/xxh3"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const commLen = 16

// Comm is the fixed-size process command name buffer supplied by the kernel.
type Comm struct {
	buffer [commLen]uint8
}

// NewComm returns a Comm that preserves the full fixed-size kernel buffer.
func NewComm(buffer [commLen]uint8) Comm {
	return Comm{buffer: buffer}
}

// NewCommFromString returns a Comm initialized from str.
func NewCommFromString(str string) Comm {
	var buffer [commLen]uint8
	copy(buffer[:], str)
	return NewComm(buffer)
}

// String converts Comm's NUL-terminated fixed-size buffer into a Go string.
func (c Comm) String() string {
	return string(stringutil.CString(c.buffer[:]))
}

// FrameMappingFileData represents a backing file for a memory mapping.
type FrameMappingFileData struct {
	// FileID is the hash of the file.
	FileID FileID
	// FileName is the base filename of the executable.
	FileName String
	// GnuBuildID is the GNU build ID from .note.gnu.build-id, if any.
	GnuBuildID string
	// GoBuildID is the Go build ID from .note.go.buildid, if any.
	GoBuildID string
}

// FrameMappingFile is an interned FrameMappingFileData reference.
type FrameMappingFile struct {
	value unique.Handle[FrameMappingFileData]
}

// NewFrameMappingFile interns given FrameMappingFileData.
func NewFrameMappingFile(data FrameMappingFileData) FrameMappingFile {
	return FrameMappingFile{value: unique.Make(data)}
}

// Value returns the dereferences FrameMappingFileData.
func (fmf FrameMappingFile) Value() FrameMappingFileData {
	return fmf.value.Value()
}

// FrameMappingData contains file backed mapping data.
type FrameMappingData struct {
	// File is a reference to data about the backing file.
	File FrameMappingFile
	// Start contains the mapping start address (file virtual address).
	Start Address
	// End contains the mapping end address (file virtual address).
	End Address
	// FileOffset is the offset within the file for this mapping.
	FileOffset uint64
}

// FrameMapping is an interned FrameMappingData reference.
type FrameMapping struct {
	value unique.Handle[FrameMappingData]
}

// NewFrameMapping interns given FrameMappingData.
func NewFrameMapping(data FrameMappingData) FrameMapping {
	return FrameMapping{value: unique.Make(data)}
}

// Valid determines if the FrameMapping is valid.
func (fmf FrameMapping) Valid() bool {
	return fmf != FrameMapping{}
}

// Value returns the dereferenced FrameMappingData.
// This can be done only if it the FrameMapping is Valid.
func (fmf FrameMapping) Value() FrameMappingData {
	return fmf.value.Value()
}

// Frame represents one frame in a stack trace.
type Frame struct {
	// FunctionName is the name of the function for the frame.
	FunctionName String
	// SourceFile is the source code file name for the frame.
	SourceFile String
	// Mapping is a reference to the mapping data to which this Frame corresponds to.
	// Available only for frames executing on a file backed memory mapping.
	Mapping FrameMapping
	// SourceLine is the source code level line number of this frame.
	SourceLine SourceLineno
	// SourceColumn is the source code level column number of this frame.
	SourceColumn SourceColumn
	// An address in ELF VA space (native frame) or line number (interpreted frame).
	AddressOrLineno AddressOrLineno
	// FunctionOffset is the line offset from function start line for the frame.
	FunctionOffset uint32
	// Type is the frame type.
	Type FrameType
}

// Frames is a list of interned frames.
type Frames []unique.Handle[Frame]

// Append interns and appends a frame to the slice of frames.
func (frames *Frames) Append(frame *Frame) {
	*frames = append(*frames, unique.Make(*frame))
}

// Trace represents a stack trace.
type Trace struct {
	CustomLabels map[String]String
	Frames       Frames

	// cachedHash memoizes the result of Hash().
	// invalidTraceHash means the hash has not been computed yet.
	cachedHash TraceHash
}

// APMHash returns the trace's hash required by the APM Agent for correlation.
// The result is not memoized.
func (t *Trace) APMHash() TraceHash {
	var buf [24]byte
	// Review and maybe update invalidTraceHash if hash function changes from FNV128A
	h := fnv.New128a()
	for _, uniqueFrame := range t.Frames {
		frame := uniqueFrame.Value()
		fileID := FileID{}
		if frame.Mapping.Valid() {
			fileID = frame.Mapping.Value().File.Value().FileID
		}
		_, _ = h.Write(fileID.Bytes())
		// Using FormatUint() or putting AppendUint() into a function leads
		// to escaping to heap (allocation).
		_, _ = h.Write(strconv.AppendUint(buf[:0], uint64(frame.AddressOrLineno), 10))
	}
	// Avoid a heap allocation by reusing the stack-allocated buffer.
	traceHash, _ := TraceHashFromBytes(h.Sum(buf[:0]))
	return traceHash
}

var customLabelHashSeed = maphash.MakeSeed()

// Hash returns a cached hash of the frames and custom labels for internal use.
// Mutations after the first call are not reflected.
func (t *Trace) Hash() TraceHash {
	if t.cachedHash != InvalidTraceHash {
		return t.cachedHash
	}
	var buf [24]byte
	h := xxh3.New128()
	for _, uniqueFrame := range t.Frames {
		frame := uniqueFrame.Value()
		fileID := FileID{}
		if frame.Mapping.Valid() {
			fileID = frame.Mapping.Value().File.Value().FileID
		}
		_, _ = h.Write(fileID.Bytes())
		n := putUint64(buf[:], uint64(frame.AddressOrLineno))
		_, _ = h.Write(buf[:n])
	}
	if len(t.CustomLabels) > 0 {
		var labelsHash uint64
		// XOR makes label order irrelevant; map keys are unique.
		for key, value := range t.CustomLabels {
			labelsHash ^= maphash.Comparable(customLabelHashSeed, [2]String{key, value})
		}
		binary.LittleEndian.PutUint64(buf[:8], labelsHash)
		_, _ = h.Write(buf[:8])
	}
	// Avoid a heap allocation by reusing the stack-allocated buffer.
	traceHash, _ := TraceHashFromBytes(h.Sum(buf[:0]))
	t.cachedHash = traceHash
	return traceHash
}

func putUint64(b []byte, v uint64) int {
	for i := range 8 {
		b[i] = byte(v)
		v >>= 8
		if v == 0 {
			return i + 1
		}
	}
	return 8
}

// EbpfTrace holds data sourced from eBPF.
type EbpfTrace struct {
	CustomLabels     map[String]String
	Comm             Comm
	KernelFrames     []uint64
	FrameData        []uint64
	FrameDataBuf     [3072]uint64
	Value            int64
	KTime            int64
	CpuID            uint32
	TID              PID
	PID              PID
	NumFrames        uint16
	Origin           uint16
	APMTraceID       APMTraceID
	APMTransactionID APMTransactionID
}

type variableDataDecoder struct {
	raw []uint8
	dst []uint64
	pos uint16
}

func (vd *variableDataDecoder) decodeBytes(end uint16, field string) ([]uint8, error) {
	if end == 0 {
		return nil, nil
	}
	if vd.pos > end || int(end) > len(vd.raw) {
		return nil, fmt.Errorf("%s end %d: not in range [%d, %d]",
			field, end, vd.pos, len(vd.raw))
	}
	data := vd.raw[vd.pos:end]
	vd.pos = (end + 7) &^ 7
	return data, nil
}

func (vd *variableDataDecoder) copyUint64(end uint16, field string) ([]uint64, error) {
	val, err := vd.decodeBytes(end, field)
	if val == nil {
		return nil, err
	}
	n := len(val) / 8
	if len(val)%8 != 0 || n > len(vd.dst) {
		return nil, fmt.Errorf("%s copy fail (size %d, max %d)",
			field, len(val), 8*len(vd.dst))
	}

	src := unsafe.Slice((*uint64)(unsafe.Pointer(unsafe.SliceData(val))), n)
	dst := vd.dst[:n]
	copy(dst, src)
	vd.dst = vd.dst[n:]
	return dst, nil
}

type LabelValidator interface {
	ValidateKey(buf []byte) ([]byte, bool)
	ValidateValue(buf []byte) ([]byte, bool)
}

func (et *EbpfTrace) Decode(hdr *support.Trace, variableData []byte, validator LabelValidator) error {
	*et = EbpfTrace{
		Comm:             NewComm(hdr.Comm),
		APMTraceID:       *(*APMTraceID)(unsafe.Pointer(&hdr.Apm_trace_id)),
		APMTransactionID: *(*APMTransactionID)(unsafe.Pointer(&hdr.Apm_transaction_id)),
		PID:              PID(hdr.Pid),
		TID:              PID(hdr.Tid),
		Origin:           hdr.Origin,
		Value:            int64(hdr.Value),
		KTime:            int64(hdr.Ktime),
		CpuID:            hdr.Cpu_id,
		NumFrames:        hdr.Num_frames,
	}
	vd := variableDataDecoder{raw: variableData, dst: et.FrameDataBuf[:]}

	var err error
	et.KernelFrames, err = vd.copyUint64(hdr.Kernel_frame_end, "kernel_frame")
	if err != nil {
		return err
	}
	et.FrameData, err = vd.copyUint64(hdr.Frame_data_end, "frame")
	if err != nil {
		return err
	}

	if labelData, err := vd.decodeBytes(hdr.Golang_label_end, "golang label"); err != nil {
		return err
	} else if len(labelData) > 0 && validator != nil {
		labels := unsafe.Slice(
			(*support.GolangLabel)(unsafe.Pointer(unsafe.SliceData(labelData))),
			len(labelData)/support.Sizeof_GolangLabel)
		et.CustomLabels = make(map[String]String, len(labels))

		for i := range labels {
			keyBytes, ok := validator.ValidateKey(labels[i].Key[:])
			if !ok {
				log.Debugf("Dropping Go custom label with empty or invalid UTF-8 name")
				continue
			}
			valBytes, ok := validator.ValidateValue(labels[i].Val[:])
			if !ok {
				log.Debugf("Dropping Go custom label %s with invalid UTF-8 value", pfunsafe.ToString(keyBytes))
				continue
			}
			et.CustomLabels[Intern(pfunsafe.ToString(keyBytes))] =
				Intern(pfunsafe.ToString(valBytes))
		}
	}
	return nil
}

// Variable length frames received from Ebpf
type EbpfFrame []uint64

// The below code must match ebpf tracemgmt.h frame_header() layout.

// NewEbpfFrameHeader creates the first word of an eBPF frame.
// Typically used for testing and synthetic cache keys only.
func NewEbpfFrameHeader(ty FrameType, ff FrameFlags, l uint8, data uint64) uint64 {
	val := uint64(ty) << 60
	val |= uint64(ff) << 56
	val |= uint64(l) << 52
	return val | data
}

// NewEbpfFrame creates a new EbpfFrame slice with given header information.
// Typically used for testing only.
func NewEbpfFrame(ty FrameType, ff FrameFlags, l uint8, data uint64) []uint64 {
	ef := make([]uint64, l)
	ef[0] = NewEbpfFrameHeader(ty, ff, l, data)
	return ef
}

func (f EbpfFrame) Type() FrameType {
	return FrameType(f[0] >> 60)
}

func (f EbpfFrame) Flags() FrameFlags {
	return FrameFlags((f[0] >> 56) & 0xf)
}

func (f EbpfFrame) Length() uint8 {
	return uint8(f[0]>>52) & 0xf
}

func (f EbpfFrame) Data() uint64 {
	return uint64(f[0]) & 0xfffffffffffff
}

func (f EbpfFrame) Variable(ndx int) uint64 {
	return f[ndx+1]
}

// ThreadLabels contains per-thread custom labels with interned keys and values.
type ThreadLabels map[String]String

// ThreadLabelDecoder decodes a per-thread custom-label payload into labels plus a
// count of entries it could not decode. Implementations must be
// concurrency-safe, and DecodeLabels must not retain or alias data, which
// points into a reused ring buffer.
type ThreadLabelDecoder interface {
	DecodeLabels(data []byte) (labels ThreadLabels, dropped int)
}
