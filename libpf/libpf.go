/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"time"
	_ "unsafe" // required to use //go:linkname for runtime.nanotime

	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/libpf/basehash"
	"github.com/elastic/otel-profiling-agent/libpf/hash"
	"github.com/elastic/otel-profiling-agent/support"
)

// UnixTime32 is another type to represent seconds since epoch.
// In most cases 32bit time values are good enough until year 2106.
// Our time series database backend uses this type for TimeStamps as well,
// so there is no need to use a different type than uint32.
// Also, Go's semantics on map[time.Time] are particularly nasty footguns,
// and since the code is mostly dealing with UNIX timestamps, we may
// as well use uint32s instead.
// To restore some semblance of type safety, we declare a type alias here.
type UnixTime32 uint32

func (t *UnixTime32) MarshalJSON() ([]byte, error) {
	return time.Unix(int64(*t), 0).UTC().MarshalJSON()
}

// Compile-time interface checks
var _ json.Marshaler = (*UnixTime32)(nil)

// NowAsUInt32 is a convenience function to avoid code repetition
func NowAsUInt32() uint32 {
	return uint32(time.Now().Unix())
}

// PID represent Unix Process ID (pid_t)
type PID int32

func (p PID) Hash32() uint32 {
	return uint32(p)
}

// FileID is used for unique identifiers for files
type FileID struct {
	basehash.Hash128
}

// UnsymbolizedFileID is used as 128-bit FileID when symbolization fails.
var UnsymbolizedFileID = NewFileID(math.MaxUint64, math.MaxUint64)

// UnknownKernelFileID is used as 128-bit FileID when the host agent isn't able to derive a FileID
// for a kernel frame.
var UnknownKernelFileID = NewFileID(math.MaxUint64-2, math.MaxUint64-2)

func NewFileID(hi, lo uint64) FileID {
	return FileID{basehash.New128(hi, lo)}
}

// FileIDFromBytes parses a byte slice into the internal data representation for a file ID.
func FileIDFromBytes(b []byte) (FileID, error) {
	// We need to check for nil since byte slice fields in protobuf messages can be optional.
	// Until improved message validation and deserialization is added, this check will prevent
	// panics.
	if b == nil {
		return FileID{}, nil
	}
	h, err := basehash.New128FromBytes(b)
	if err != nil {
		return FileID{}, err
	}
	return FileID{h}, nil
}

// FileIDFromString parses a hexadecimal notation of a file ID into the internal data
// representation.
func FileIDFromString(s string) (FileID, error) {
	hash128, err := basehash.New128FromString(s)
	if err != nil {
		return FileID{}, err
	}
	return FileID{hash128}, nil
}

// FileIDFromBase64 converts a base64url encoded file ID into its binary representation.
// We store binary fields as keywords as base64 URL encoded strings.
// But when retrieving binary fields, ES sends them as base64 STD encoded strings.
func FileIDFromBase64(s string) (FileID, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s) // allows - and _ in input
	if err != nil {
		// ES uses StdEncoding when marshaling binary fields
		bytes, err = base64.RawStdEncoding.DecodeString(s) // allows + and / in input
		if err != nil {
			return FileID{}, fmt.Errorf("failed to decode to fileID %s: %v", s, err)
		}
	}
	if len(bytes) != 16 {
		return FileID{}, fmt.Errorf("unexpected input size (expected 16 exeBytes): %d",
			len(bytes))
	}

	return FileIDFromBytes(bytes)
}

// Hash32 returns a 32 bits hash of the input.
// It's main purpose is to be used as key for caching.
func (f FileID) Hash32() uint32 {
	return uint32(f.Hi())
}

func (f FileID) Equal(other FileID) bool {
	return f.Hash128.Equal(other.Hash128)
}

func (f FileID) Less(other FileID) bool {
	return f.Hash128.Less(other.Hash128)
}

// Compare returns an integer comparing two hashes lexicographically.
// The result will be 0 if f == other, -1 if f < other, and +1 if f > other.
func (f FileID) Compare(other FileID) int {
	return f.Hash128.Compare(other.Hash128)
}

// Compile-time interface checks
var _ encoding.TextUnmarshaler = (*FileID)(nil)
var _ encoding.TextMarshaler = (*FileID)(nil)

// PackageID is used for unique identifiers for packages
type PackageID struct {
	basehash.Hash128
}

// PackageIDFromBytes parses a byte slice into the internal data representation for a PackageID.
func PackageIDFromBytes(b []byte) (PackageID, error) {
	h, err := basehash.New128FromBytes(b)
	if err != nil {
		return PackageID{}, err
	}
	return PackageID{h}, nil
}

// Equal returns true if both PackageIDs are equal.
func (h PackageID) Equal(other PackageID) bool {
	return h.Hash128.Equal(other.Hash128)
}

// String returns the string representation for the package ID.
func (h PackageID) String() string {
	return h.StringNoQuotes()
}

// PackageIDFromString returns a PackageID from its string representation.
func PackageIDFromString(str string) (PackageID, error) {
	hash128, err := basehash.New128FromString(str)
	if err != nil {
		return PackageID{}, err
	}
	return PackageID{hash128}, nil
}

// TraceHash represents the unique hash of a trace
type TraceHash struct {
	basehash.Hash128
}

func NewTraceHash(hi, lo uint64) TraceHash {
	return TraceHash{basehash.New128(hi, lo)}
}

// TraceHashFromBytes parses a byte slice of a trace hash into the internal data representation.
func TraceHashFromBytes(b []byte) (TraceHash, error) {
	h, err := basehash.New128FromBytes(b)
	if err != nil {
		return TraceHash{}, err
	}
	return TraceHash{h}, nil
}

// TraceHashFromString parses a hexadecimal notation of a trace hash into the internal data
// representation.
func TraceHashFromString(s string) (TraceHash, error) {
	hash128, err := basehash.New128FromString(s)
	if err != nil {
		return TraceHash{}, err
	}
	return TraceHash{hash128}, nil
}

func (h TraceHash) Equal(other TraceHash) bool {
	return h.Hash128.Equal(other.Hash128)
}

func (h TraceHash) Less(other TraceHash) bool {
	return h.Hash128.Less(other.Hash128)
}

// EncodeTo encodes the hash into the base64 encoded representation
// and stores it in the provided destination byte array.
// The length of the destination must be at least EncodedLen().
func (h TraceHash) EncodeTo(dst []byte) {
	base64.RawURLEncoding.Encode(dst, h.Bytes())
}

// EncodedLen returns the length of the hash's base64 representation.
func (TraceHash) EncodedLen() int {
	// TraceHash is 16 bytes long, the base64 representation is one base64 byte per 6 bits.
	return ((16)*8)/6 + 1
}

// Hash32 returns a 32 bits hash of the input.
// It's main purpose is to be used for LRU caching.
func (h TraceHash) Hash32() uint32 {
	return uint32(h.Lo())
}

// Compile-time interface checks
var _ encoding.TextUnmarshaler = (*TraceHash)(nil)
var _ encoding.TextMarshaler = (*TraceHash)(nil)

// AddressOrLineno represents a line number in an interpreted file or an offset into
// a native file. TODO(thomasdullien): check with regards to JSON marshaling/demarshaling.
type AddressOrLineno uint64

// Address represents an address, or offset within a process
type Address uint64

// Hash32 returns a 32 bits hash of the input.
// It's main purpose is to be used as key for caching.
func (adr Address) Hash32() uint32 {
	return uint32(adr.Hash())
}

func (adr Address) Hash() uint64 {
	return hash.Uint64(uint64(adr))
}

// InterpVersion represents the version of an interpreter
type InterpVersion string

// SourceLineno represents a line number within a source file. It is intended to be used for the
// source line numbers associated with offsets in native code, or for source line numbers in
// interpreted code.
type SourceLineno uint64

// InterpType variables can hold one of the interpreter type values defined below.
type InterpType int

const (
	// UnknownInterp signifies that the interpreter is unknown.
	UnknownInterp InterpType = support.FrameMarkerUnknown
	// PHP identifies the PHP interpreter.
	PHP InterpType = support.FrameMarkerPHP
	// PHPJIT identifies PHP JIT processes.
	PHPJIT InterpType = support.FrameMarkerPHPJIT
	// Python identifies the Python interpreter.
	Python InterpType = support.FrameMarkerPython
	// Native identifies native code.
	Native InterpType = support.FrameMarkerNative
	// Kernel identifies kernel code.
	Kernel InterpType = support.FrameMarkerKernel
	// HotSpot identifies the Java HotSpot VM.
	HotSpot InterpType = support.FrameMarkerHotSpot
	// Ruby identifies the Ruby interpreter.
	Ruby InterpType = support.FrameMarkerRuby
	// Perl identifies the Perl interpreter.
	Perl InterpType = support.FrameMarkerPerl
	// V8 identifies the V8 interpreter.
	V8 InterpType = support.FrameMarkerV8
)

// Frame converts the interpreter type into the corresponding frame type.
func (i InterpType) Frame() FrameType {
	return FrameType(i)
}

var interpTypeToString = map[InterpType]string{
	UnknownInterp: "unknown",
	PHP:           "php",
	PHPJIT:        "phpjit",
	Python:        "python",
	Native:        "native",
	Kernel:        "kernel",
	HotSpot:       "jvm",
	Ruby:          "ruby",
	Perl:          "perl",
	V8:            "v8",
}

// String converts the frame type int to the related string value to be displayed in the UI.
func (i InterpType) String() string {
	if result, ok := interpTypeToString[i]; ok {
		return result
	}
	// nolint:goconst
	return "<invalid>"
}

// FrameType defines the type of frame. This usually corresponds to the interpreter type that
// emitted it, but can additionally contain meta-information like error frames.
//
// A frame type can represent one of the following things:
//
//   - A successfully unwound frame. This is represented simply as the `InterpType` ID.
//   - A partial (non-critical failure), indicated by ORing the `InterpType` ID with the error bit.
//   - A fatal failure that caused further unwinding to be aborted. This is indicated using the
//     special value support.FrameMarkerAbort (0xFF). It thus also contains the error bit, but
//     does not fit into the `InterpType` enum.
type FrameType int

// Convenience shorthands to create various frame types.
//
// Code should not compare against the constants below directly, but instead use the provided
// methods to query the required information (IsError, Interpreter, ...) to improve forward
// compatibility and clarify intentions.
const (
	// UnknownFrame indicates a frame of an unknown interpreter.
	// If this appears, it's likely a bug somewhere.
	UnknownFrame FrameType = support.FrameMarkerUnknown
	// PHPFrame identifies PHP interpreter frames.
	PHPFrame FrameType = support.FrameMarkerPHP
	// PHPJITFrame identifies PHP JIT interpreter frames.
	PHPJITFrame FrameType = support.FrameMarkerPHPJIT
	// PythonFrame identifies the Python interpreter frames.
	PythonFrame FrameType = support.FrameMarkerPython
	// NativeFrame identifies native frames.
	NativeFrame FrameType = support.FrameMarkerNative
	// KernelFrame identifies kernel frames.
	KernelFrame FrameType = support.FrameMarkerKernel
	// HotSpotFrame identifies Java HotSpot VM frames.
	HotSpotFrame FrameType = support.FrameMarkerHotSpot
	// RubyFrame identifies the Ruby interpreter frames.
	RubyFrame FrameType = support.FrameMarkerRuby
	// PerlFrame identifies the Perl interpreter frames.
	PerlFrame FrameType = support.FrameMarkerPerl
	// V8Frame identifies the V8 interpreter frames.
	V8Frame FrameType = support.FrameMarkerV8
	// AbortFrame identifies frames that report that further unwinding was aborted due to an error.
	AbortFrame FrameType = support.FrameMarkerAbort
)

// Interpreter returns the interpreter that produced the frame.
func (ty FrameType) Interpreter() InterpType {
	switch ty {
	case support.FrameMarkerAbort, support.FrameMarkerUnknown:
		return UnknownInterp
	default:
		return InterpType(ty &^ support.FrameMarkerErrorBit)
	}
}

// IsInterpType checks whether the frame type belongs to the given interpreter.
func (ty FrameType) IsInterpType(ity InterpType) bool {
	return ity == ty.Interpreter()
}

// Error adds the error bit into the frame type.
func (ty FrameType) Error() FrameType {
	return ty | support.FrameMarkerErrorBit
}

// IsError checks whether the frame is an error frame.
func (ty FrameType) IsError() bool {
	return ty&support.FrameMarkerErrorBit != 0
}

// String implements the Stringer interface.
func (ty FrameType) String() string {
	switch ty {
	case support.FrameMarkerAbort:
		return "abort-marker"
	default:
		interp := ty.Interpreter()
		if ty.IsError() {
			return fmt.Sprintf("%s-error", interp)
		}
		return interp.String()
	}
}

// The different types of packages that we process
type PackageType int32

func (t PackageType) String() string {
	if res, ok := packageTypeToString[t]; ok {
		return res
	}
	// nolint:goconst
	return "<unknown>"
}

const (
	PackageTypeDeb = iota
	PackageTypeRPM
	PackageTypeCustomSymbols
	PackageTypeAPK
)

var packageTypeToString = map[PackageType]string{
	PackageTypeDeb:           "deb",
	PackageTypeRPM:           "rpm",
	PackageTypeCustomSymbols: "custom",
	PackageTypeAPK:           "apk",
}

// The different types of source package objects that we process
type SourcePackageType int32

const (
	SourcePackageTypeDeb = iota
	SourcePackageTypeRPM
)

const (
	CodeIndexingPackageTypeDeb    = "deb"
	CodeIndexingPackageTypeRpm    = "rpm"
	CodeIndexingPackageTypeCustom = "custom"
	CodeIndexingPackageTypeApk    = "apk"
)

type CodeIndexingMessage struct {
	SourcePackageName    string `json:"sourcePackageName"`
	SourcePackageVersion string `json:"sourcePackageVersion"`
	MirrorName           string `json:"mirrorName"`
	ForceRetry           bool   `json:"forceRetry"`
}

// LocalFSPackageID is a fake package identifier, indicating that a particular file was not part of
// a package, but was extracted directly from a local filesystem.
var LocalFSPackageID = PackageID{
	basehash.New128(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
}

// The different types of packages that we process
type FileType int32

const (
	FileTypeNative = iota
	FileTypePython
)

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

type TraceAndCounts struct {
	Hash          TraceHash
	Timestamp     UnixTime32
	Count         uint16
	Comm          string
	PodName       string
	ContainerName string
}

type FrameMetadata struct {
	FileID         FileID
	AddressOrLine  AddressOrLineno
	LineNumber     SourceLineno
	FunctionOffset uint32
	FunctionName   string
	Filename       string
}

// StackFrame represents a stack frame - an ID for the file it belongs to, an
// address (in case it is a binary file) or a line number (in case it is a source
// file), and a type that says what type of frame this is (Python, PHP, native,
// more languages in the future).
// type StackFrame struct {
//	file          FileID
//	addressOrLine AddressOrLineno
//	frameType     InterpType
// }

// ComputeFileCRC32 computes the CRC32 hash of a file
func ComputeFileCRC32(filePath string) (int32, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("unable to compute CRC32 for %v: %v", filePath, err)
	}
	defer f.Close()

	h := crc32.NewIEEE()

	_, err = io.Copy(h, f)
	if err != nil {
		return 0, fmt.Errorf("unable to compute CRC32 for %v: %v (failed copy)", filePath, err)
	}

	return int32(h.Sum32()), nil
}

// OnDiskFileIdentifier can be used as unique identifier for a file.
// It is a structure to identify a particular file on disk by
// deviceID and inode number.
type OnDiskFileIdentifier struct {
	DeviceID uint64 // dev_t as reported by stat.
	InodeNum uint64 // ino_t should fit into 64 bits
}

func (odfi OnDiskFileIdentifier) Hash32() uint32 {
	return uint32(hash.Uint64(odfi.InodeNum) + odfi.DeviceID)
}

// GetOnDiskFileIdentifier builds a unique identifier of a given filename
// based on the information we can extract from stat.
func GetOnDiskFileIdentifier(filename string) (OnDiskFileIdentifier, error) {
	var st unix.Stat_t
	err := unix.Stat(filename, &st)
	if err != nil {
		// Putting filename into the error makes it escape to the heap.
		// Since this is a common path, we try to avoid it.
		// Currently, the only caller discards the error string anyway.
		return OnDiskFileIdentifier{}, fmt.Errorf("failed to stat: %v",
			err)
	}
	return OnDiskFileIdentifier{
			DeviceID: st.Dev,
			InodeNum: st.Ino},
		nil
}

// TimeToInt64 converts a time.Time to an int64. It preserves the "zero-ness" across the
// conversion, which means a zero Time is converted to 0.
func TimeToInt64(t time.Time) int64 {
	if t.IsZero() {
		// t.UnixNano() is undefined if t.IsZero() is true.
		return 0
	}
	return t.UnixNano()
}

// Int64ToTime converts an int64 to a time.Time. It preserves the "zero-ness" across the
// conversion, which means 0 is converted to a zero time.Time (instead of the Unix epoch).
func Int64ToTime(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(0, t)
}

// KTime stores a time value, retrieved from a monotonic clock, in nanoseconds
type KTime int64

// GetKTime gets the current time in same nanosecond format as bpf_ktime_get_ns() eBPF call
// This relies runtime.nanotime to use CLOCK_MONOTONIC. If this changes, this needs to
// be adjusted accordingly. Using this internal is superior in performance, as it is able
// to use the vDSO to query the time without syscall.
//
//go:noescape
//go:linkname GetKTime runtime.nanotime
func GetKTime() KTime

// Void allows to use maps as sets without memory allocation for the values.
// From the "Go Programming Language":
//
//	The struct type with no fields is called the empty struct, written struct{}. It has size zero
//	and carries no information but may be useful nonetheless. Some Go programmers
//	use it instead of bool as the value type of a map that represents a set, to emphasize
//	that only the keys are significant, but the space saving is marginal and the syntax more
//	cumbersome, so we generally avoid it.
type Void struct{}

// Range describes a range with Start and End values.
type Range struct {
	Start uint64
	End   uint64
}
