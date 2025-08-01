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
	"path"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

// GetMappings returns this error when no mappings can be extracted.
var ErrNoMappings = errors.New("no mappings")

// systemProcess provides an implementation of the Process interface for a
// process that is currently running on this machine.
type systemProcess struct {
	pid libpf.PID
	tid libpf.PID

	mainThreadExit bool
	remoteMemory   remotememory.RemoteMemory

	fileToMapping map[string]*Mapping
}

var _ Process = &systemProcess{}

var bufPool sync.Pool

// mappingParseBufferSize defines the initial buffer size used to store lines from
// /proc/PID/maps during parsing of mappings.

const mappingParseBufferSize = 256

func init() {
	bufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, mappingParseBufferSize)
			return &buf
		},
	}
}

// New returns an object with Process interface accessing it
func New(pid, tid libpf.PID) Process {
	return &systemProcess{
		pid:          pid,
		tid:          tid,
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

func parseMappings(mapsFile io.Reader) ([]Mapping, uint32, error) {
	numParseErrors := uint32(0)
	mappings := make([]Mapping, 0, 32)
	scanner := bufio.NewScanner(mapsFile)
	scanBuf := bufPool.Get().(*[]byte)
	if scanBuf == nil {
		return mappings, 0, errors.New("failed to get memory from sync pool")
	}
	defer func() {
		// Reset memory and return it for reuse.
		for j := 0; j < len(*scanBuf); j++ {
			(*scanBuf)[j] = 0x0
		}
		bufPool.Put(scanBuf)
	}()

	scanner.Buffer(*scanBuf, 8192)
	for scanner.Scan() {
		var fields [6]string
		var addrs [2]string
		var devs [2]string

		line := stringutil.ByteSlice2String(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			numParseErrors++
			continue
		}
		if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
			numParseErrors++
			continue
		}

		mapsFlags := fields[1]
		if len(mapsFlags) < 3 {
			numParseErrors++
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
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			log.Debugf("inode: failed to convert %s to uint64: %v", fields[4], err)
			numParseErrors++
			continue
		}

		if stringutil.SplitN(fields[3], ":", devs[:]) < 2 {
			numParseErrors++
			continue
		}
		major, err := strconv.ParseUint(devs[0], 16, 64)
		if err != nil {
			log.Debugf("major device: failed to convert %s to uint64: %v", devs[0], err)
			numParseErrors++
			continue
		}
		minor, err := strconv.ParseUint(devs[1], 16, 64)
		if err != nil {
			log.Debugf("minor device: failed to convert %s to uint64: %v", devs[1], err)
			numParseErrors++
			continue
		}
		device := major<<8 + minor

		var path libpf.String
		if inode == 0 {
			if fields[5] == "[vdso]" {
				// Map to something filename looking with synthesized inode
				path = VdsoPathName
				device = 0
				inode = vdsoInode
			} else if fields[5] == "" {
				// This is an anonymous mapping, keep it
			} else {
				// Ignore other mappings that are invalid, non-existent or are special pseudo-files
				continue
			}
		} else {
			path = libpf.Intern(trimMappingPath(fields[5]))
		}

		vaddr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			log.Debugf("vaddr: failed to convert %s to uint64: %v", addrs[0], err)
			numParseErrors++
			continue
		}
		vend, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			log.Debugf("vend: failed to convert %s to uint64: %v", addrs[1], err)
			numParseErrors++
			continue
		}
		length := vend - vaddr

		fileOffset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			log.Debugf("fileOffset: failed to convert %s to uint64: %v", fields[2], err)
			numParseErrors++
			continue
		}

		mappings = append(mappings, Mapping{
			Vaddr:      vaddr,
			Length:     length,
			Flags:      flags,
			FileOffset: fileOffset,
			Device:     device,
			Inode:      inode,
			Path:       path,
		})
	}
	return mappings, numParseErrors, scanner.Err()
}

// GetMappings will process the mappings file from proc. Additionally,
// a reverse map from mapping filename to a Mapping node is built to allow
// OpenELF opening ELF files using the corresponding proc map_files entry.
// WARNING: This implementation does not support calling GetMappings
// concurrently with itself, or with OpenELF.
func (sp *systemProcess) GetMappings() ([]Mapping, uint32, error) {
	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", sp.pid))
	if err != nil {
		return nil, 0, err
	}
	defer mapsFile.Close()

	mappings, numParseErrors, err := parseMappings(mapsFile)
	if err != nil {
		return mappings, numParseErrors, err
	}

	if len(mappings) == 0 {
		// We could test for main thread exit here by checking for zombie state
		// in /proc/sp.pid/stat but it's simpler to assume that this is the case
		// and try extracting mappings for a different thread. Since we stopped
		// processing /proc at agent startup, it's not possible that the agent
		// will sample a process without mappings
		log.Debugf("PID: %v main thread exit", sp.pid)
		sp.mainThreadExit = true

		if sp.pid == sp.tid {
			return mappings, numParseErrors, ErrNoMappings
		}

		log.Debugf("TID: %v extracting mappings", sp.tid)
		mapsFileAlt, err := os.Open(fmt.Sprintf("/proc/%d/task/%d/maps", sp.pid, sp.tid))
		// On all errors resulting from trying to get mappings from a different thread,
		// return ErrNoMappings which will keep the PID tracked in processmanager and
		// allow for a future iteration to try extracting mappings from a different thread.
		// This is done to deal with race conditions triggered by thread exits (we do not want
		// the agent to unload process metadata when a thread exits but the process is still
		// alive).
		if err != nil {
			return mappings, numParseErrors, ErrNoMappings
		}
		defer mapsFileAlt.Close()
		mappings, numParseErrors, err = parseMappings(mapsFileAlt)
		if err != nil || len(mappings) == 0 {
			return mappings, numParseErrors, ErrNoMappings
		}
	}

	fileToMapping := make(map[string]*Mapping, len(mappings))
	for idx := range mappings {
		m := &mappings[idx]
		fileToMapping[m.Path.String()] = m
	}
	sp.fileToMapping = fileToMapping
	return mappings, numParseErrors, nil
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
	if sp.mainThreadExit {
		// Neither /proc/sp.pid/map_files nor /proc/sp.pid/task/sp.tid/map_files
		// nor /proc/sp.pid/root exist if main thread has exited, so we use the
		// mapping path directly under the sp.tid root.
		rootPath := fmt.Sprintf("/proc/%v/task/%v/root", sp.pid, sp.tid)
		return path.Join(rootPath, m.Path.String())
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
	return pfelf.Open(path.Join("/proc", strconv.Itoa(int(sp.pid)), "root", file))
}

func (sp *systemProcess) ExtractAsFile(file string) (string, error) {
	return path.Join("/proc", strconv.Itoa(int(sp.pid)), "root", file), nil
}
