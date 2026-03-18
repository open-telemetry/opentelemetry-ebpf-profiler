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
var VdsoPathName = libpf.Intern("linux-vdso.1.so")

// vdsoInode is the synthesized inode number for VDSO mappings.
const vdsoInode = 50

// RawMapping is the ephemeral representation of a memory mapping as parsed
// from /proc/pid/maps. Path is a plain string that may reference the
// parser's internal buffer and must not be stored beyond the
// IterateMappings callback. Use ToMapping() to produce a Mapping with
// an interned Path that is safe to store long-term.
type RawMapping struct {
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
	// May reference an internal buffer recycled after iteration.
	Path string
}

func (m *RawMapping) IsExecutable() bool {
	return m.Flags&elf.PF_X == elf.PF_X
}

func (m *RawMapping) IsAnonymous() bool {
	return !m.IsFileBacked() && !m.IsVDSO()
}

func (m *RawMapping) IsFileBacked() bool {
	return m.Path != "" && !m.IsVDSO() && !m.IsMemFD()
}

func (m *RawMapping) IsMemFD() bool {
	return strings.HasPrefix(m.Path, "/memfd:")
}

func (m *RawMapping) IsVDSO() bool {
	return m.Path == VdsoPathName.String()
}

// ToMapping converts to a Mapping with an interned Path. Only call this
// for mappings you intend to keep.
func (m *RawMapping) ToMapping() Mapping {
	return Mapping{
		Vaddr:      m.Vaddr,
		Length:     m.Length,
		Flags:      m.Flags,
		FileOffset: m.FileOffset,
		Device:     m.Device,
		Inode:      m.Inode,
		Path:       libpf.Intern(m.Path),
	}
}

// Mapping is the stable representation of a memory mapping with an
// interned Path. Produced by RawMapping.ToMapping() after filtering.
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
	// Path is the interned file path for file-backed and special mappings.
	Path libpf.String
}

func (m *Mapping) IsExecutable() bool {
	return m.Flags&elf.PF_X == elf.PF_X
}

func (m *Mapping) IsAnonymous() bool {
	return !m.IsFileBacked() && !m.IsVDSO()
}

func (m *Mapping) IsFileBacked() bool {
	return m.Path != libpf.NullString && !m.IsVDSO() && !m.IsMemFD()
}

func (m *Mapping) IsMemFD() bool {
	return strings.HasPrefix(m.Path.String(), "/memfd:")
}

func (m *Mapping) IsVDSO() bool {
	return m.Path == VdsoPathName
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

	// IterateMappings parses process memory mappings and calls callback
	// for each mapping. The callback receives a RawMapping whose Path
	// may reference an internal buffer recycled after iteration; use
	// ToMapping() to produce a Mapping safe to store long-term.
	// The callback is responsible for filtering out unwanted mappings.
	IterateMappings(callback func(m RawMapping) bool) (uint32, error)

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
