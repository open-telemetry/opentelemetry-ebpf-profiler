package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"debug/elf"
	"errors"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type TestInstance struct {
	interpreter.InstanceStubs
	info                  libc.LibcInfo
	syncMappings          []process.RawMapping
	usesAnonymousMappings bool
}

func (ti *TestInstance) UpdateLibcInfo(_ interpreter.EbpfHandler, _ libpf.PID, info libc.LibcInfo) error {
	ti.info = info
	return nil
}

func (ti *TestInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (ti *TestInstance) UsesAnonymousMappings() bool {
	return ti.usesAnonymousMappings
}

func (ti *TestInstance) SynchronizeMappings(_ interpreter.EbpfHandler,
	_ reporter.ExecutableReporter, _ process.Process, mappings []process.RawMapping,
) error {
	ti.syncMappings = append([]process.RawMapping(nil), mappings...)
	return nil
}

type testInterpreterData struct {
	attach func(interpreter.EbpfHandler, libpf.PID, libpf.Address, remotememory.RemoteMemory) (
		interpreter.Instance, error)
}

func (td *testInterpreterData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	return td.attach(ebpf, pid, bias, rm)
}

func (td *testInterpreterData) Unload(interpreter.EbpfHandler) {}

type testEbpfHandler struct {
	pidPageMappingInfoUpdates []struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}
}

func (h *testEbpfHandler) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (h *testEbpfHandler) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (h *testEbpfHandler) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidInterpreterMapping(
	libpf.PID, lpm.Prefix, uint8, host.FileID, uint64,
) error {
	return nil
}

func (h *testEbpfHandler) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error {
	return nil
}

func (h *testEbpfHandler) RemoveReportedPID(libpf.PID) {}

func (h *testEbpfHandler) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

func (h *testEbpfHandler) UpdateExeIDToStackDeltas(
	host.FileID, []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	return 0, nil
}

func (h *testEbpfHandler) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (h *testEbpfHandler) UpdateStackDeltaPages(host.FileID, []uint16, uint16, uint64) error {
	return nil
}

func (h *testEbpfHandler) DeleteStackDeltaPage(host.FileID, uint64) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix,
	fileID, bias uint64,
) error {
	h.pidPageMappingInfoUpdates = append(h.pidPageMappingInfoUpdates, struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{pid: pid, prefix: prefix, fileID: fileID, bias: bias})
	return nil
}

func (h *testEbpfHandler) DeletePidPageMappingInfo(libpf.PID, []lpm.Prefix) (uint64, error) {
	return 0, nil
}

func (h *testEbpfHandler) CollectMetrics() []metrics.Metric {
	return nil
}

func (h *testEbpfHandler) SupportsLPMTrieBatchOperations() bool {
	return false
}

type testProcess struct {
	pid      libpf.PID
	exe      libpf.String
	mappings []process.RawMapping
}

func (tp *testProcess) PID() libpf.PID {
	return tp.pid
}

func (tp *testProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (tp *testProcess) GetProcessMeta(process.MetaConfig) process.ProcessMeta {
	return process.ProcessMeta{}
}

func (tp *testProcess) GetExe() (libpf.String, error) {
	return tp.exe, nil
}

func (tp *testProcess) IterateMappings(callback func(process.RawMapping) bool) (uint32, error) {
	for _, m := range tp.mappings {
		if !callback(m) {
			return 0, process.ErrCallbackStopped
		}
	}
	return 0, nil
}

func (tp *testProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, nil
}

func (tp *testProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (tp *testProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nil, errors.New("not implemented")
}

func (tp *testProcess) GetMappingFileLastModified(*process.RawMapping) int64 {
	return 0
}

func (tp *testProcess) CalculateMappingFileID(*process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, errors.New("not implemented")
}

func (tp *testProcess) Close() error {
	return nil
}

func (tp *testProcess) OpenELF(string) (*pfelf.File, error) {
	return nil, errors.New("not implemented")
}

type runtimeInstance struct {
	interpreter.InstanceStubs
	name    string
	version string
	ok      bool
}

func (r *runtimeInstance) RuntimeInfo() (string, string, bool) {
	return r.name, r.version, r.ok
}

func (r *runtimeInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	return nil
}

func TestSelectProcessRuntime(t *testing.T) {
	exeOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	libOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}

	tests := map[string]struct {
		interps     map[util.OnDiskFileIdentifier]interpreter.Instance
		exeOID      util.OnDiskFileIdentifier
		wantName    string
		wantVersion string
	}{
		"exe runtime wins over embedded runtime": {
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &runtimeInstance{name: "go", version: "1.23.4", ok: true},
				libOID: &runtimeInstance{name: "cpython", version: "3.11.4", ok: true},
			},
			exeOID:      exeOID,
			wantName:    "go",
			wantVersion: "1.23.4",
		},
		"falls back to sole HLL when exe is a launcher": {
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				libOID: &runtimeInstance{name: "openjdk", version: "17.0.8", ok: true},
			},
			exeOID:      exeOID,
			wantName:    "openjdk",
			wantVersion: "17.0.8",
		},
		"exe runtime opting out yields nothing": {
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &runtimeInstance{ok: false},
			},
			exeOID: exeOID,
		},
		"no interpreters yields nothing": {
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{},
			exeOID:  exeOID,
		},
		"deterministically picks smallest (name, version) among non-exe runtimes": {
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				libOID:                     &runtimeInstance{name: "cpython", version: "3.11.4", ok: true},
				{DeviceID: 1, InodeNum: 3}: &runtimeInstance{name: "ruby", version: "3.2.0", ok: true},
			},
			exeOID:      exeOID,    // absent from interps, so the fallback runs
			wantName:    "cpython", // "cpython" < "ruby", independent of map order
			wantVersion: "3.11.4",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotName, gotVersion := selectProcessRuntime(test.interps, test.exeOID)
			assert.Equal(t, test.wantName, gotName)
			assert.Equal(t, test.wantVersion, gotVersion)
		})
	}
}

func TestAssignLibcInfoMergesLibcInfo(t *testing.T) {
	assert := assert.New(t)

	pid := libpf.PID(1)
	odid := util.OnDiskFileIdentifier{
		DeviceID: 1,
		InodeNum: 1,
	}

	interp := TestInstance{}

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				odid: &interp,
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {},
		},
	}

	libcInfoWithTSD := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{
			Offset:     8,
			Multiplier: 8,
			Indirect:   0,
		},
		DTVInfo: libc.DTVInfo{},
	}
	pm.assignLibcInfo(pid, &libcInfoWithTSD)

	assert.Equal(libcInfoWithTSD, interp.info)

	libcInfoWithDTV := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{},
		DTVInfo: libc.DTVInfo{
			Offset:     -8,
			Multiplier: 16,
		},
	}

	merged := libcInfoWithTSD
	merged.Merge(libcInfoWithDTV)

	pm.assignLibcInfo(pid, &libcInfoWithDTV)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)

	pm.assignLibcInfo(pid, &merged)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)
}

func TestHandleNewInterpreterRecordsAnonymousMappingInterestLocally(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oid)
	require.True(anonymousMappingsWanted)
}

func TestHandleNewInterpreterDoesNotAssignOnAttachFailure(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	attachErr := errors.New("attach failed")
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return nil, attachErr
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.ErrorIs(err, attachErr)
	require.False(anonymousMappingsWanted)
	require.NotContains(pm.interpreters, pid)
}

func TestHandleNewInterpreterKeepsExistingInterpreter(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oldOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	newOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf: &testEbpfHandler{},
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oldOID: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, newOID, data, true)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oldOID)
	require.Contains(pm.interpreters[pid], newOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersClearsAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(
		pid, libpf.Set[util.OnDiskFileIdentifier]{})

	require.NotContains(pm.interpreters, pid)
	require.False(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersKeepsAnonymousMappingInterestWhenInterpreterRemains(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	keptOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	removedOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				keptOID:    &TestInstance{usesAnonymousMappings: true},
				removedOID: &TestInstance{usesAnonymousMappings: true},
			},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(pid,
		libpf.Set[util.OnDiskFileIdentifier]{keptOID: libpf.Void{}})

	require.Contains(pm.interpreters[pid], keptOID)
	require.NotContains(pm.interpreters[pid], removedOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessPIDExitRemovesInterpreters(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				{DeviceID: 1, InodeNum: 2}: &TestInstance{usesAnonymousMappings: true},
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.processPIDExit(pid)
	require.NotContains(pm.interpreters, pid)
}

func TestSynchronizeProcessUpdatesAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{pid: pid})

	require.Equal([]struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{{pid: pid, prefix: dummyPrefix}}, ebpf.pidPageMappingInfoUpdates)
}

func TestSynchronizeProcessSkipsDllMappingsWithoutAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	instance := &TestInstance{}
	interpreterMapping := process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x1000,
		Flags:  elf.PF_R | elf.PF_X,
		Device: oid.DeviceID,
		Inode:  oid.InodeNum,
		Path:   "/tmp/interpreter",
	}
	pm := &ProcessManager{
		ebpf:                     &testEbpfHandler{},
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: instance},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				mappings: []Mapping{
					{
						Vaddr:  libpf.Address(interpreterMapping.Vaddr),
						Length: interpreterMapping.Length,
						Device: interpreterMapping.Device,
						Inode:  interpreterMapping.Inode,
						FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
							File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
								FileID:   libpf.NewFileID(1, 0),
								FileName: libpf.Intern("interpreter"),
							}),
							Start: 0,
							End:   libpf.Address(interpreterMapping.Length),
						}),
					},
				},
			},
		},
		exitEvents: make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{
		pid: pid,
		mappings: []process.RawMapping{
			interpreterMapping,
			{
				Vaddr:  0x3000,
				Length: 0x1000,
				Flags:  elf.PF_R,
				Device: 3,
				Inode:  4,
				Path:   "/tmp/assembly.dll",
			},
		},
	})

	require.Empty(instance.syncMappings)
}

func TestSynchronizeProcessResolvesTopLevelRuntime(t *testing.T) {
	const exePath = "/opt/app/bin/agent"
	exeOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	libOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}

	rawMapping := func(vaddr uint64, oid util.OnDiskFileIdentifier, path string) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: 0x1000,
			Flags:  elf.PF_R | elf.PF_X,
			Device: oid.DeviceID,
			Inode:  oid.InodeNum,
			Path:   path,
		}
	}
	keptMapping := func(vaddr uint64, oid util.OnDiskFileIdentifier) Mapping {
		return Mapping{
			Vaddr:  libpf.Address(vaddr),
			Length: 0x1000,
			Device: oid.DeviceID,
			Inode:  oid.InodeNum,
			FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
				File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
					FileID:   libpf.NewFileID(oid.DeviceID, oid.InodeNum),
					FileName: libpf.Intern("x"),
				}),
				Start: 0,
				End:   0x1000,
			}),
		}
	}

	tests := map[string]struct {
		interps     map[util.OnDiskFileIdentifier]interpreter.Instance
		preMeta     process.ProcessMeta
		wantName    string
		wantVersion string
	}{
		"top-level exe runtime wins over embedded runtime": {
			// Go binary that dlopen'd CPython: report the runtime whose DSO is
			// the executable, not the embedded one.
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &runtimeInstance{name: "go", version: "1.23.4", ok: true},
				libOID: &runtimeInstance{name: "cpython", version: "3.11.4", ok: true},
			},
			wantName:    "go",
			wantVersion: "1.23.4",
		},
		"runtime is not overwritten once set": {
			// Executable unchanged (meta preserved) and runtime already resolved:
			// the recompute must leave it untouched (fill-once).
			interps: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &runtimeInstance{name: "go", version: "1.23.4", ok: true},
			},
			preMeta: process.ProcessMeta{
				Executable:     libpf.Intern(exePath),
				RuntimeName:    "cpython",
				RuntimeVersion: "3.11.4",
			},
			wantName:    "cpython",
			wantVersion: "3.11.4",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pid := libpf.PID(123)
			mappings := make([]Mapping, 0, len(test.interps))
			raws := make([]process.RawMapping, 0, len(test.interps))
			vaddr := uint64(0x1000)
			for oid := range test.interps {
				path := "/usr/lib/libembedded.so"
				if oid == exeOID {
					path = exePath
				}
				mappings = append(mappings, keptMapping(vaddr, oid))
				raws = append(raws, rawMapping(vaddr, oid, path))
				vaddr += 0x1000
			}
			pm := &ProcessManager{
				ebpf: &testEbpfHandler{},
				interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
					pid: test.interps,
				},
				pidToProcessInfo: map[libpf.PID]*processInfo{
					pid: {mappings: mappings, meta: test.preMeta},
				},
				exitEvents: make(map[libpf.PID]times.KTime),
			}

			pm.SynchronizeProcess(&testProcess{
				pid:      pid,
				exe:      libpf.Intern(exePath),
				mappings: raws,
			})

			assert.Equal(t, test.wantName, pm.pidToProcessInfo[pid].meta.RuntimeName)
			assert.Equal(t, test.wantVersion, pm.pidToProcessInfo[pid].meta.RuntimeVersion)
		})
	}
}

func TestIsInterpreterMapping(t *testing.T) {
	tests := []struct {
		name string
		m    process.RawMapping
		want bool
	}{
		{
			name: "anonymous executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X},
			want: true,
		},
		{
			name: "anonymous non-executable",
			m:    process.RawMapping{Flags: elf.PF_R},
		},
		{
			name: "dll",
			m:    process.RawMapping{Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
			want: true,
		},
		{
			name: "file backed executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isInterpreterMapping(&test.m))
		})
	}
}

func TestInterpreterMappingCollectorFlushesFirstPassMappingsAfterEnable(t *testing.T) {
	collector := newInterpreterMappingCollector(8)
	pending := []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x2000, Flags: elf.PF_R},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x4000, Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
	}
	for _, m := range pending {
		collector.add(m, false)
	}
	require.Empty(t, collector.mappings())

	collector.enable()
	collector.add(process.RawMapping{
		Vaddr: 0x5000,
		Flags: elf.PF_R,
		Path:  "/tmp/assembly.dll",
	}, true)

	require.Equal(t, []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x5000, Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
	}, collector.mappings())
}
