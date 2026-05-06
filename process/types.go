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
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// VdsoPathName is the path to use for VDSO mappings.
const VdsoPathName = "linux-vdso.1.so"

// vdsoInode is the synthesized inode number for VDSO mappings.
const vdsoInode = 50

// RawMapping represents a memory mapping parsed from /proc/pid/maps or a coredump.
//
// WARNING: When produced by the systemProcess IterateMappings implementation,
// Path may reference an internal scanner buffer that is recycled after the
// iteration completes. Callers that need to store the mapping beyond the
// callback scope must intern the Path via libpf.Intern to detach it from the
// buffer and deduplicate identical paths across mappings.
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
	// When received from IterateMappings, this may point into an internal
	// buffer. The caller must use libpf.Intern to detach it before storing
	// the mapping long-term.
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
	return m.Path == VdsoPathName
}

func (m *RawMapping) GetOnDiskFileIdentifier() util.OnDiskFileIdentifier {
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
	// process context
	ProcessContextInfo processcontext.Info
}

// Process is the interface to inspect ELF coredump/process.
// The current implementations do not allow concurrent access to this interface
// from different goroutines. As an exception ELFOpener, OpenELFMapping, and
// the returned GetRemoteMemory object are safe for concurrent use.
type Process interface {
	// PID returns the process identifier.
	PID() libpf.PID

	// GetMachineData reads machine specific data from the target process.
	GetMachineData() MachineData

	// GetProcessMeta returns process specific metadata.
	GetProcessMeta(MetaConfig) ProcessMeta

	// GetExe returns the executable path of the process.
	GetExe() (libpf.String, error)

	// IterateMappings parses process memory mappings and calls the
	// callback for each mapping. The RawMapping's Path field may reference
	// an internal buffer that is recycled after the iteration completes;
	// callers must use libpf.Intern to detach the Path before storing the
	// mapping beyond the callback scope. Returning false from the callback
	// stops iteration and causes ErrCallbackStopped to be returned.
	IterateMappings(callback func(m RawMapping) bool) (uint32, error)

	// GetThreads reads the process thread states.
	GetThreads() ([]ThreadInfo, error)

	// GetRemoteMemory returns a remote memory reader accessing the target process.
	GetRemoteMemory() remotememory.RemoteMemory

	// OpenMappingFile returns ReadAtCloser accessing the backing file of the mapping.
	OpenMappingFile(*RawMapping) (ReadAtCloser, error)

	// OpenELFMapping opens a memory mapping as an ELF file. The mapping must
	// originate from this Process (via IterateMappings), passing a foreign
	// mapping has undefined results.
	OpenELFMapping(*RawMapping) (*pfelf.File, error)

	// GetMappingFileLastModifed returns the timestamp when the backing file was last modified
	// or zero if an error occurs or mapping file is not accessible via filesystem.
	GetMappingFileLastModified(*RawMapping) int64

	// CalculateMappingFileID calculates FileID of the backing file.
	CalculateMappingFileID(*RawMapping) (libpf.FileID, error)

	io.Closer

	pfelf.ELFOpener
}
