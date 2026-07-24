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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

// ErrNoMappings is returned when no mappings can be extracted.
var ErrNoMappings = errors.New("no mappings")

// ErrCallbackStopped is returned when the IterateMappings callback returns
// false, signaling that iteration was intentionally interrupted.
var ErrCallbackStopped = errors.New("IterateMappings stopped by callback")

// ErrMappingFileUnavailable signals OpenELFMapping to fall back to
// OpenELF. Returned both when the implementation has no backing-file
// route (CoredumpProcess) and when a specific file is missing from the
// backing store (StoreCoredump bundle miss).
var ErrMappingFileUnavailable = errors.New("mapping backing file unavailable")

const (
	containerSource = "[0-9a-f]{64}"
	taskSource      = "[0-9a-f]{32}-\\d+"
)

//nolint:lll
var (
	// expLine matches a line in the /proc/<pid>/cgroup file. It has a submatch for the last element (path), which contains the container ID. Supports both cgroup v1 and v2.
	expLine = regexp.MustCompile(`^\d+:[^:]*:(.+)$`)

	// Inspired from https://github.com/DataDog/dd-otel-host-profiler/blob/1e50a36d4c3a8a87f0cc828f37b48455ec436e55/containermetadata/container.go#L32-L47 with the following changes to handle unit tests in process_test.go:
	// - support prefix after `scope` to handle "0::/system.slice/docker-b1eba9dfaeba29d8b80532a574a03ea3cac29384327f339c26da13649e2120df.scope/init"
	// - remove uuidSource to doesn't match "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-868f9513-eee8-457d-8e36-1b37ae8ae622.scope"
	expContainerID = regexp.MustCompile(fmt.Sprintf(`(%s|%s)(?:\.scope)?(?:/[a-z]+)?$`, containerSource, taskSource))
)

// systemProcess provides an implementation of the Process interface for a
// process that is currently running on this machine.
type systemProcess struct {
	pid        libpf.PID
	tid        libpf.PID
	procBase   string // "/proc/<pid>/"
	rootFsPath string

	mainThreadExit bool
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
func New(pid, tid libpf.PID, rootFsPath string) Process {
	return &systemProcess{
		pid:        pid,
		tid:        tid,
		rootFsPath: rootFsPath,
		procBase:   path.Join(rootFsPath, "/proc", strconv.Itoa(int(pid))) + "/",
	}
}

func (sp *systemProcess) PID() libpf.PID {
	return sp.pid
}

func (sp *systemProcess) GetMachineData() MachineData {
	return MachineData{Machine: pfelf.CurrentMachine}
}

func (sp *systemProcess) GetExe() (libpf.String, error) {
	str, err := os.Readlink(sp.procBase + "exe")
	if err != nil {
		return libpf.NullString, err
	}
	return libpf.Intern(str), nil
}

func (sp *systemProcess) GetProcessMeta(cfg MetaConfig) ProcessMeta {
	var processName libpf.String
	exePath, _ := sp.GetExe()
	if name, err := os.ReadFile(sp.procBase + "comm"); err == nil {
		processName = libpf.Intern(pfunsafe.ToString(name))
	}

	var envVarMap map[libpf.String]libpf.String
	if len(cfg.IncludeEnvVars) > 0 {
		if envVars, err := os.ReadFile(sp.procBase + "environ"); err == nil {
			envVarMap = make(map[libpf.String]libpf.String, len(cfg.IncludeEnvVars))
			// environ has environment variables separated by a null byte (hex: 00)
			for envVar := range strings.SplitSeq(pfunsafe.ToString(envVars), "\000") {
				var fields [2]string
				if stringutil.SplitN(envVar, "=", fields[:]) < 2 {
					continue
				}
				if _, ok := cfg.IncludeEnvVars[fields[0]]; ok {
					envVarMap[libpf.Intern(fields[0])] = libpf.Intern(fields[1])
				}
			}
		}
	}

	containerID, err := sp.extractContainerID()
	if err != nil {
		log.Debugf("Failed extracting containerID for %d: %v", sp.pid, err)
	}
	return ProcessMeta{
		Name:         processName,
		Executable:   exePath,
		ContainerID:  containerID,
		EnvVariables: envVarMap,
	}
}

// parseContainerID parses cgroup v1 and v2 container IDs
func parseContainerID(cgroupFile io.Reader) libpf.String {
	scanner := bufio.NewScanner(cgroupFile)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	for scanner.Scan() {
		b := scanner.Bytes()
		if bytes.Equal(b, []byte("0::/")) {
			continue // Skip a common case
		}
		line := pfunsafe.ToString(b)
		m := expLine.FindStringSubmatchIndex(line)
		if len(m) == 4 {
			sub := line[m[2]:m[3]]
			if parts := expContainerID.FindStringSubmatchIndex(sub); len(parts) == 4 {
				return libpf.Intern(sub[parts[2]:parts[3]])
			}
		}
		log.Debugf("Could not extract container ID from line: %s", line)
	}

	// No containerID could be extracted
	return libpf.NullString
}

// extractContainerID returns the containerID for pid (supports both cgroup v1 and v2)
func (sp *systemProcess) extractContainerID() (libpf.String, error) {
	cgroupFile, err := os.Open(path.Join(sp.procBase, "cgroup"))
	if err != nil {
		return libpf.NullString, err
	}
	defer cgroupFile.Close()

	return parseContainerID(cgroupFile), nil
}

// CgroupRootInode returns the inode of /proc/<pid>/root/sys/fs/cgroup, which identifies
// the cgroup namespace root visible to the given process, unaffected by namespace masking.
func CgroupRootInode(pid libpf.PID, rootFs string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path.Join(rootFs, fmt.Sprintf("/proc/%d/root/sys/fs/cgroup", pid)), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// DetectSelfContainerIDViaInode detects the current process's container ID by matching
// cgroup directory inodes. When the process runs in a private cgroup namespace (cgroup v2),
// /proc/self/cgroup returns a path relative to the namespace root (e.g. "0::/"), making it
// impossible to extract the container ID via the standard path. However, stat("/sys/fs/cgroup")
// returns the inode of the process's actual cgroup directory on the host, unaffected by
// namespace masking. This function walks the host's cgroup tree (via
// /proc/1/root/sys/fs/cgroup) to find the directory whose inode matches, then extracts
// the container ID from its path.
func DetectSelfContainerIDViaInode() (libpf.String, uint64, error) {
	const hostCgroupRoot = "/proc/1/root/sys/fs/cgroup"

	var selfStat unix.Stat_t
	if err := unix.Stat("/sys/fs/cgroup", &selfStat); err != nil {
		return libpf.NullString, 0, fmt.Errorf("failed to stat /sys/fs/cgroup: %w", err)
	}
	selfIno := selfStat.Ino

	var matched libpf.String
	err := filepath.WalkDir(hostCgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d == nil {
				return err // root is inaccessible
			}
			return nil // skip inaccessible subdirectories
		}
		if !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			return nil
		}
		if st.Ino == selfIno {
			if parts := expContainerID.FindStringSubmatch(path); len(parts) == 2 {
				matched = libpf.Intern(parts[1])
			}
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return libpf.NullString, 0, fmt.Errorf("failed to walk host cgroup tree: %w", err)
	}
	return matched, selfIno, nil
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

func iterateMappings(mapsFile io.Reader, callback func(m RawMapping) bool) (uint32, error) {
	numParseErrors := uint32(0)
	scanner := bufio.NewScanner(mapsFile)
	scanBuf := bufPool.Get().(*[]byte)
	if scanBuf == nil {
		return 0, errors.New("failed to get memory from sync pool")
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

		// WARNING: line (and all substrings derived from it, including the
		// Path field of the emitted RawMapping) points into scanBuf which is
		// recycled after iteration. Callers must intern Path (libpf.Intern)
		// before storing.
		line := pfunsafe.ToString(scanner.Bytes())
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

		var path string
		if inode == 0 {
			if fields[5] == "[vdso]" {
				// Map to something filename looking with synthesized inode
				path = VdsoPathName
				device = 0
				inode = vdsoInode
			} else if fields[5] == "" {
				// This is an anonymous mapping, keep it
			} else if strings.HasPrefix(fields[5], "[anon:") {
				// Keep named anonymous mapping
				path = fields[5]
			} else {
				// Ignore other mappings that are invalid, non-existent or are special pseudo-files
				continue
			}
		} else {
			path = trimMappingPath(fields[5])
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

		if !callback(RawMapping{
			Vaddr:      vaddr,
			Length:     length,
			Flags:      flags,
			FileOffset: fileOffset,
			Device:     device,
			Inode:      inode,
			Path:       path,
		}) {
			return numParseErrors, ErrCallbackStopped
		}
	}
	return numParseErrors, scanner.Err()
}

func (sp *systemProcess) IterateMappings(callback func(m RawMapping) bool) (uint32, error) {
	mapsFile, err := os.Open(sp.procBase + "maps")
	if err != nil {
		return 0, err
	}
	defer mapsFile.Close()

	gotMappings := false
	trackedCallback := func(m RawMapping) bool {
		gotMappings = true
		return callback(m)
	}

	numParseErrors, err := iterateMappings(mapsFile, trackedCallback)
	if err != nil {
		return numParseErrors, err
	}

	if !gotMappings {
		// We could test for main thread exit here by checking for zombie state
		// in /proc/sp.pid/stat but it's simpler to assume that this is the case
		// and try extracting mappings for a different thread. Since we stopped
		// processing /proc at agent startup, it's not possible that the agent
		// will sample a process without mappings
		log.Debugf("PID: %v main thread exit", sp.pid)
		sp.mainThreadExit = true

		if sp.pid == sp.tid {
			return numParseErrors, ErrNoMappings
		}

		log.Debugf("TID: %v extracting mappings", sp.tid)
		mapsFileAlt, err := os.Open(fmt.Sprintf("%stask/%d/maps", sp.procBase, sp.tid))
		// On all errors resulting from trying to get mappings from a different thread,
		// return ErrNoMappings which will keep the PID tracked in processmanager and
		// allow for a future iteration to try extracting mappings from a different thread.
		// This is done to deal with race conditions triggered by thread exits (we do not want
		// the agent to unload process metadata when a thread exits but the process is still
		// alive).
		if err != nil {
			return numParseErrors, ErrNoMappings
		}
		defer mapsFileAlt.Close()
		numParseErrors, err := iterateMappings(mapsFileAlt, trackedCallback)
		if err != nil || !gotMappings {
			return numParseErrors, ErrNoMappings
		}
	}

	return numParseErrors, nil
}

func (sp *systemProcess) GetThreads() ([]ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (sp *systemProcess) Close() error {
	return nil
}

func (sp *systemProcess) GetRemoteMemory() (remotememory.RemoteMemory, error) {
	return remotememory.NewProcessVirtualMemory(sp.pid, sp.rootFsPath)
}

// extractMapping reads the mapping's memory into an in-memory reader.
// Used to access mappings that have no usable backing file (e.g. VDSO).
func extractMapping(pr Process, m *RawMapping) (*bytes.Reader, error) {
	rm, err := pr.GetRemoteMemory()
	if err != nil {
		return nil, fmt.Errorf("unable to get remote memory for PID %d: %w", pr.PID(), err)
	}
	defer rm.Close()
	data := make([]byte, m.Length)
	if _, err := rm.ReadAt(data, int64(m.Vaddr)); err != nil {
		return nil, fmt.Errorf("unable to extract mapping at %#x from PID %d",
			m.Vaddr, pr.PID())
	}
	return bytes.NewReader(data), nil
}

// openInProcRoot opens a file within a process's filesystem namespace.
func (sp *systemProcess) openInProcRoot(filePath string) (*os.File, error) {
	return openInRoot(path.Join(sp.procBase, "root"), filePath)
}

// getMappingFile opens the backing file for a mapping and returns an open file descriptor.
// The caller is responsible for closing the returned file.
func (sp *systemProcess) getMappingFile(m *RawMapping) (*os.File, error) {
	if !m.IsFileBacked() {
		return nil, errors.New("no backing file for anonymous memory")
	}
	if sp.mainThreadExit {
		// Neither /proc/sp.pid/map_files nor /proc/sp.pid/task/sp.tid/map_files
		// nor /proc/sp.pid/root exist if main thread has exited, so we use the
		// mapping path directly under the sp.tid root.
		rootPath := fmt.Sprintf("%stask/%d/root", sp.procBase, sp.tid)
		f, err := openInRoot(rootPath, m.Path)
		if err != nil {
			return nil, err
		}
		// Verify inode and device match the mapping to detect file substitution.
		if err = checkInodeDeviceMapping(f, m); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
	filename := fmt.Sprintf("%smap_files/%x-%x", sp.procBase, m.Vaddr, m.Vaddr+m.Length)
	return os.Open(filename)
}

func (sp *systemProcess) OpenMappingFile(m *RawMapping) (ReadAtCloser, error) {
	return sp.getMappingFile(m)
}

func (sp *systemProcess) GetMappingFileLastModified(m *RawMapping) int64 {
	f, err := sp.getMappingFile(m)
	if err != nil {
		return 0
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err == nil {
		return st.Mtim.Nano()
	}
	return 0
}

// vdsoFileID caches the VDSO FileID. This assumes there is single instance of
// VDSO for the system.
var vdsoFileID libpf.FileID

func (sp *systemProcess) CalculateMappingFileID(m *RawMapping) (libpf.FileID, error) {
	if m.IsVDSO() {
		if vdsoFileID != (libpf.FileID{}) {
			return vdsoFileID, nil
		}
		vdso, err := extractMapping(sp, m)
		if err != nil {
			return libpf.FileID{}, fmt.Errorf("failed to extract VDSO: %v", err)
		}
		vdsoFileID, err = libpf.FileIDFromExecutableReader(vdso)
		return vdsoFileID, err
	}
	f, err := sp.getMappingFile(m)
	if err != nil {
		return libpf.FileID{}, fmt.Errorf("failed to get mapping file: %v", err)
	}
	defer f.Close()
	return libpf.FileIDFromExecutableReader(f)
}

func (sp *systemProcess) OpenELF(file string) (*pfelf.File, error) {
	// Open the file using the process-specific root. Callers that have a
	// RawMapping should use OpenELFMapping instead, which can open deleted
	// or replaced files via /proc/<pid>/map_files.
	// Use openat2 with RESOLVE_IN_ROOT to prevent symlink escapes from the container.
	f, err := sp.openInProcRoot(file)
	if err != nil {
		return nil, err
	}
	return pfelf.NewFileOwned(f)
}

// OpenELFMapping opens a memory mapping as an ELF file. VDSO is read
// from process memory; other mappings go through OpenMappingFile so
// systemProcess can use /proc/<pid>/map_files for deleted-file safety.
// Only ErrMappingFileUnavailable triggers a fallback to OpenELF; other
// OpenMappingFile errors are wrapped and returned.
func OpenELFMapping(pr Process, m *RawMapping) (*pfelf.File, error) {
	if m.IsVDSO() {
		vdso, err := extractMapping(pr, m)
		if err != nil {
			return nil, fmt.Errorf("failed to extract VDSO: %v", err)
		}
		return pfelf.NewFile(vdso, 0, false)
	}
	rac, err := pr.OpenMappingFile(m)
	if err != nil {
		if errors.Is(err, ErrMappingFileUnavailable) {
			return pr.OpenELF(m.Path)
		}
		return nil, fmt.Errorf("OpenMappingFile path=%q vaddr=%#x: %w", m.Path, m.Vaddr, err)
	}
	return pfelf.NewFileOwned(rac)
}
