// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This file defines the interface to access a Process state.

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"debug/elf"
	"io"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// VdsoPathName is the path used for VDSO mappings.
const VdsoPathName = "linux-vdso.1.so"

// vdsoInode is the synthesized inode number for VDSO mappings.
const vdsoInode = 50

// Mapping contains information about a memory mapping.
type Mapping struct {
	// Vaddr is the virtual memory start for this mapping.
	Vaddr uint64
	// Length is the length of the mapping.
	Length uint64
	// Flags contains the mapping flags and permissions.
	Flags elf.ProgFlag
	// FileOffset contains for file backed mappings the offset from the file start.
	FileOffset uint64
	// Device holds the device ID where the file is located.
	Device uint64
	// Inode holds the mapped file's inode number.
	Inode uint64
	// Path is the file path for file-backed and special mappings.
	// For live processes parsed from /proc/pid/maps, this string may
	// reference an internal buffer that is recycled. Callers must call
	// Retain() on any mapping they store beyond the iteration callback.
	Path string
}

func (m *Mapping) IsExecutable() bool {
	return m.Flags&elf.PF_X == elf.PF_X
}

// IsAnonymous returns true for mappings without a backing file.
// This includes memfd mappings and /dev/zero.
func (m *Mapping) IsAnonymous() bool {
	return !m.IsFileBacked() && !m.IsVDSO()
}

// IsFileBacked returns true for mappings backed by a regular file on disk.
// Excludes memfd, vdso, and anonymous mappings.
func (m *Mapping) IsFileBacked() bool {
	return m.Path != "" && !m.IsVDSO() && !m.IsMemFD()
}

func (m *Mapping) IsMemFD() bool {
	return strings.HasPrefix(m.Path, "/memfd:")
}

func (m *Mapping) IsVDSO() bool {
	return m.Path == VdsoPathName
}

// Retain makes a copy of Path so the mapping can safely outlive the
// parser's internal buffer. Must be called inside the IterateMappings
// callback for any mapping that will be stored beyond the callback.
// Safe to call on mappings from implementations that don't use buffer
// recycling (e.g. coredump) -- it's a no-op clone in that case.
func (m *Mapping) Retain() {
	m.Path = strings.Clone(m.Path)
}

func (m *Mapping) GetOnDiskFileIdentifier() util.OnDiskFileIdentifier {
	return util.OnDiskFileIdentifier{
		DeviceID: m.Device,
		InodeNum: m.Inode,
	}
}

// ThreadInfo contains the information about a thread CPU state needed for unwinding.
type ThreadInfo struct {
	// TPBase contains the Thread Pointer Base value.
	TPBase uint64
	// GPRegs contains the CPU state (registers) for the thread.
	GPRegs []byte
	// LWP is the Light Weight Process ID (thread ID).
	LWP uint32
}

// MachineData contains machine specific information about the process.
type MachineData struct {
	// Machine is the Process Machine type.
	Machine elf.Machine
	// CodePACMask contains the PAC mask for code pointers. ARM64 specific, otherwise 0.
	CodePACMask uint64
	// DataPACMask contains the PAC mask for data pointers. ARM64 specific, otherwise 0.
	DataPACMask uint64
}

// ReadAtCloser combines the io.ReaderAt and io.Closer interfaces.
type ReadAtCloser interface {
	io.ReaderAt
	io.Closer
}

// MetaConfig provides options that influences gathering ProcessMeta.
type MetaConfig struct {
	// IncludeEnvVars holds a list of env vars that should be captured from the process.
	IncludeEnvVars libpf.Set[string]
}

// ProcessMeta contains metadata about a tracked process.
type ProcessMeta struct {
	// process name retrieved from /proc/PID/comm
	Name libpf.String
	// executable path retrieved from /proc/PID/exe
	Executable libpf.String
	// process env vars from /proc/PID/environ
	EnvVariables map[libpf.String]libpf.String
	// container ID retrieved from /proc/PID/cgroup
	ContainerID libpf.String
}

// Process is the interface to inspect ELF coredump/process.
// The current implementations do not allow concurrent access to this interface
// from different goroutines. As an exception the ELFOpener and the returned
// GetRemoteMemory object are safe for concurrent use.
type Process interface {
	// PID returns the process identifier.
	PID() libpf.PID

	// GetMachineData reads machine specific data from the target process.
	GetMachineData() MachineData

	// GetProcessMeta returns process specific metadata.
	GetProcessMeta(MetaConfig) ProcessMeta

	// GetExe returns the executable path of the process.
	GetExe() (libpf.String, error)

	// IterateMappings parses process memory mappings and calls callback for
	// each valid mapping. Path is set to the raw file path for file-backed
	// mappings. The callback must call m.Retain() on any mapping it stores
	// beyond the callback scope, because Path may reference an internal
	// buffer that is recycled after iteration. Parsing stops early if
	// callback returns false.
	IterateMappings(callback func(m Mapping) bool) (uint32, error)

	// GetThreads reads the process thread states.
	GetThreads() ([]ThreadInfo, error)

	// GetRemoteMemory returns a remote memory reader accessing the target process.
	GetRemoteMemory() remotememory.RemoteMemory

	// OpenMappingFile returns ReadAtCloser accessing the backing file of the mapping.
	OpenMappingFile(*Mapping) (ReadAtCloser, error)

	// GetMappingFileLastModifed returns the timestamp when the backing file was last modified
	// or zero if an error occurs or mapping file is not accessible via filesystem.
	GetMappingFileLastModified(*Mapping) int64

	// CalculateMappingFileID calculates FileID of the backing file.
	CalculateMappingFileID(*Mapping) (libpf.FileID, error)

	io.Closer

	pfelf.ELFOpener
}
