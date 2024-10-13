// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// systemProcess provides an implementation of the Process interface for a
// process that is currently running on this machine.
type systemProcess struct {
	pid libpf.PID

	remoteMemory remotememory.RemoteMemory

	fileToMapping map[string]*Mapping
}

var _ Process = &systemProcess{}

// New returns an object with Process interface accessing it
func New(pid libpf.PID) Process {
	return &systemProcess{
		pid:          pid,
		remoteMemory: remotememory.NewProcessVirtualMemory(pid),
	}
}

func (sp *systemProcess) PID() libpf.PID {
	return sp.pid
}

func (sp *systemProcess) GetMachineData() MachineData {
	return MachineData{Machine: currentMachine}
}

func trimMappingPath(path string) string {
	// Trim the deleted indication from the path.
	// See path_with_deleted in linux/fs/d_path.c
	path = strings.TrimSuffix(path, " (deleted)")
	if path == "/dev/zero" {
		// Some JIT engines map JIT area from /dev/zero
		// make it anonymous.
		return ""
	}
	return path
}

func parseMappings(mapsFile io.Reader, pid libpf.PID) ([]Mapping, error) {
	mappings := make([]Mapping, 0)
	scanner := bufio.NewScanner(mapsFile)
	buf := make([]byte, 512)
	scanner.Buffer(buf, 8192)
	for scanner.Scan() {
		var fields [6]string
		var addrs [2]string
		var devs [2]string

		line := stringutil.ByteSlice2String(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			continue
		}
		if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
			continue
		}

		mapsFlags := fields[1]
		if len(mapsFlags) < 3 {
			continue
		}
		flags := elf.ProgFlag(0)
		if mapsFlags[0] == 'r' {
			flags |= elf.PF_R
		}
		if mapsFlags[1] == 'w' {
			flags |= elf.PF_W
		}
		if mapsFlags[2] == 'x' {
			flags |= elf.PF_X
		}

		// Ignore non-readable and non-executable mappings
		if flags&(elf.PF_R|elf.PF_X) == 0 {
			continue
		}
		inode := util.DecToUint64(fields[4])
		path := fields[5]
		if stringutil.SplitN(fields[3], ":", devs[:]) < 2 {
			continue
		}
		device := util.HexToUint64(devs[0])<<8 + util.HexToUint64(devs[1])

		if inode == 0 {
			if path == "[vdso]" {
				// Map to something filename looking with synthesized inode
				path = vdsoPathName
				device = 0
				inode = vdsoInode
			} else if path != "" {
				// Ignore [vsyscall] and similar executable kernel
				// pages we don't care about
				continue
			}
		} else {
			path = "/proc/" + strconv.Itoa(int(pid)) + "/root/" + trimMappingPath(path)
			// path = trimMappingPath(path)
			path = strings.Clone(path)
		}

		vaddr := util.HexToUint64(addrs[0])
		mappings = append(mappings, Mapping{
			Vaddr:      vaddr,
			Length:     util.HexToUint64(addrs[1]) - vaddr,
			Flags:      flags,
			FileOffset: util.HexToUint64(fields[2]),
			Device:     device,
			Inode:      inode,
			Path:       path,
		})
	}
	return mappings, scanner.Err()
}

// GetMappings will process the mappings file from proc. Additionally,
// a reverse map from mapping filename to a Mapping node is built to allow
// OpenELF opening ELF files using the corresponding proc map_files entry.
// WARNING: This implementation does not support calling GetMappings
// concurrently with itself, or with OpenELF.
func (sp *systemProcess) GetMappings() ([]Mapping, error) {
	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", sp.pid))
	if err != nil {
		return nil, err
	}
	defer mapsFile.Close()

	mappings, err := parseMappings(mapsFile, sp.pid)
	if err == nil {
		fileToMapping := make(map[string]*Mapping)
		for idx := range mappings {
			m := &mappings[idx]
			if m.Inode != 0 {
				fileToMapping[m.Path] = m
			}
		}
		sp.fileToMapping = fileToMapping
	}
	return mappings, err
}

func (sp *systemProcess) GetThreads() ([]ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (sp *systemProcess) Close() error {
	return nil
}

func (sp *systemProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return sp.remoteMemory
}

func (sp *systemProcess) extractMapping(m *Mapping) (*bytes.Reader, error) {
	data := make([]byte, m.Length)
	_, err := sp.remoteMemory.ReadAt(data, int64(m.Vaddr))
	if err != nil {
		return nil, fmt.Errorf("unable to extract mapping at %#x from PID %d",
			m.Vaddr, sp.pid)
	}
	return bytes.NewReader(data), nil
}

func (sp *systemProcess) getMappingFile(m *Mapping) string {
	if m.IsAnonymous() || m.IsVDSO() {
		return ""
	}
	return fmt.Sprintf("/proc/%v/map_files/%x-%x", sp.pid, m.Vaddr, m.Vaddr+m.Length)
}

func (sp *systemProcess) OpenMappingFile(m *Mapping) (ReadAtCloser, error) {
	filename := sp.getMappingFile(m)
	if filename == "" {
		return nil, errors.New("no backing file for anonymous memory")
	}
	return os.Open(filename)
}

func (sp *systemProcess) GetMappingFileLastModified(m *Mapping) int64 {
	filename := sp.getMappingFile(m)
	if filename != "" {
		var st unix.Stat_t
		if err := unix.Stat(filename, &st); err == nil {
			return st.Mtim.Nano()
		}
	}
	return 0
}

// vdsoFileID caches the VDSO FileID. This assumes there is single instance of
// VDSO for the system.
var vdsoFileID libpf.FileID = libpf.UnsymbolizedFileID

func (sp *systemProcess) CalculateMappingFileID(m *Mapping) (libpf.FileID, error) {
	if m.IsVDSO() {
		if vdsoFileID != libpf.UnsymbolizedFileID {
			return vdsoFileID, nil
		}
		vdso, err := sp.extractMapping(m)
		if err != nil {
			return libpf.FileID{}, fmt.Errorf("failed to extract VDSO: %v", err)
		}
		vdsoFileID, err = libpf.FileIDFromExecutableReader(vdso)
		return vdsoFileID, err
	}
	return libpf.FileIDFromExecutableFile(sp.getMappingFile(m))
}

func (sp *systemProcess) OpenELF(file string) (*pfelf.File, error) {
	// Always open via map_files as it can open deleted files if available.
	// No fallback is attempted:
	// - if the process exited, the fallback will error also (/proc/>PID> is gone)
	// - if the error is due to ELF content, same error will occur in both cases
	// - if the process unmapped the ELF, its data is no longer needed
	if m, ok := sp.fileToMapping[file]; ok {
		if m.IsVDSO() {
			vdso, err := sp.extractMapping(m)
			if err != nil {
				return nil, fmt.Errorf("failed to extract VDSO: %v", err)
			}
			return pfelf.NewFile(vdso, 0, false)
		}
		return pfelf.Open(sp.getMappingFile(m))
	}

	// Fall back to opening the file using the process specific root
	return pfelf.Open(fmt.Sprintf("/proc/%v/root/%s", sp.pid, file))
}
