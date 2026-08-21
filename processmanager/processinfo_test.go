package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"debug/elf"
	"errors"
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
	"go.opentelemetry.io/ebpf-profiler/procmeta"
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
	// exeID is what GetExecutableFileIdentifier reports; the zero value stands
	// for an executable that could not be identified.
	exeID util.OnDiskFileIdentifier
}

func (tp *testProcess) PID() libpf.PID {
	return tp.pid
}

func (tp *testProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (tp *testProcess) GetProcessMeta(enrichers []process.MetaEnricher) process.Meta {
	meta := process.Meta{Executable: tp.exe}
	for _, e := range enrichers {
		e.EnrichMeta(fmt.Sprintf("/proc/%d/", tp.pid), &meta)
	}
	return meta
}

func (tp *testProcess) GetExe() (libpf.String, error) {
	return tp.exe, nil
}

func (tp *testProcess) GetExecutableFileIdentifier() (util.OnDiskFileIdentifier, error) {
	if tp.exeID == (util.OnDiskFileIdentifier{}) {
		return util.OnDiskFileIdentifier{}, errors.New("no executable")
	}
	return tp.exeID, nil
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
			name: "prctl-named anonymous non-executable",
			m: process.RawMapping{
				Flags: elf.PF_R,
				Path:  "[anon:Ruby:rb_jit_reserve_addr_space]",
			},
			want: true,
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
		{Vaddr: 0x2000, Flags: elf.PF_R, Path: "[anon:Ruby:rb_jit_reserve_addr_space]"},
		{Vaddr: 0x2800, Flags: elf.PF_R},
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
		{Vaddr: 0x2000, Flags: elf.PF_R, Path: "[anon:Ruby:rb_jit_reserve_addr_space]"},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x5000, Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
	}, collector.mappings())
}

// TestSynchronizeProcessRunEnrichers verifies that meta enrichers run at process
// discovery and again when the executable changes, so that enricher-produced
// ExtraMeta is not lost when process metadata is refetched.
func TestSynchronizeProcessRunEnrichers(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	key := libpf.Intern("test.key")
	enricherCalls := 0
	enricher := process.MetaEnricherFunc(func(procBase string, meta *process.Meta) {
		enricherCalls++
		require.Equal(fmt.Sprintf("/proc/%d/", pid), procBase)
		meta.ExtraMeta = map[libpf.String]string{key: meta.Executable.String()}
	})

	pm := newTestProcessManager([]process.MetaEnricher{enricher}, nil)

	// Process first seen: gather and enrich metadata.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricherCalls)
	meta, _ := pm.metaForPID(pid)
	require.Equal("foobar", meta.ExtraMeta[key])

	// Unchanged executable: don't refetch metadata, don't enrich.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricherCalls)

	// Executable changed: refetch metadata and enrich.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobarbaz")})
	require.Equal(2, enricherCalls)
	meta, _ = pm.metaForPID(pid)
	require.Equal("foobarbaz", meta.ExtraMeta[key])
}

// testResourceEnricher is a ResourceEnricher whose behaviour each test controls
// through enrich.
type testResourceEnricher struct {
	cfg    procmeta.ResourceConfig
	calls  int
	reqs   []procmeta.ResourceRequest
	enrich func(req *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool)
}

func (e *testResourceEnricher) ResourceConfig() procmeta.ResourceConfig {
	return e.cfg
}

func (e *testResourceEnricher) EnrichResource(req *procmeta.ResourceRequest) (
	*pcommon.Resource, bool,
) {
	e.calls++
	e.reqs = append(e.reqs, *req)
	if e.enrich == nil {
		return nil, false
	}
	return e.enrich(req, e.calls)
}

// resourceWithAttr builds a single-attribute resource.
func resourceWithAttr(key, value string) *pcommon.Resource {
	r := pcommon.NewResource()
	r.Attributes().PutStr(key, value)
	return &r
}

// resourceAttrs flattens a resource's string attributes, or returns nil.
func resourceAttrs(r *pcommon.Resource) map[string]string {
	if r == nil {
		return nil
	}
	attrs := make(map[string]string, r.Attributes().Len())
	r.Attributes().Range(func(k string, v pcommon.Value) bool {
		attrs[k] = v.Str()
		return true
	})
	return attrs
}

func newTestProcessManager(metaEnrichers []process.MetaEnricher,
	resourceEnrichers []procmeta.ResourceEnricher,
) *ProcessManager {
	return &ProcessManager{
		ebpf:              &testEbpfHandler{},
		interpreters:      make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo:  make(map[libpf.PID]*processInfo),
		exitEvents:        make(map[libpf.PID]times.KTime),
		metaEnrichers:     metaEnrichers,
		resourceEnrichers: resourceEnrichers,
		mappingFilters:    newMappingFilters(resourceEnrichers),
	}
}

// TestSynchronizeProcessRunsResourceEnrichers verifies that resource enrichers run
// on every synchronization, unlike meta enrichers, so attributes resolving after
// first observation are still picked up.
func TestSynchronizeProcessRunsResourceEnrichers(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	// Contributes nothing on the first call, then an attribute on the second, as a
	// late-resolving enricher would.
	enricher := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			if call == 1 {
				return nil, false
			}
			return resourceWithAttr("late.attr", "resolved"), true
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricher.calls)
	_, resource := pm.metaForPID(pid)
	require.Nil(resource)
	require.Equal(pid, enricher.reqs[0].Process.PID())

	// Same executable: the meta enrichers would not run, but this one does.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(2, enricher.calls)
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"late.attr": "resolved"}, resourceAttrs(resource))

	// Reporting no change keeps the published contribution.
	enricher.enrich = func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
		return nil, false
	}
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(3, enricher.calls)
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"late.attr": "resolved"}, resourceAttrs(resource))

	// Reporting a change with a nil resource withdraws it.
	enricher.enrich = func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
		return nil, true
	}
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource = pm.metaForPID(pid)
	require.Nil(resource)
}

// TestSynchronizeProcessResourceEnricherStateKeptUntilExec verifies that derived
// state is kept across synchronizations of one program and dropped on the one after
// an exec — an empty slot being the whole signal an enricher gets, and needs.
func TestSynchronizeProcessResourceEnricherStateKeptUntilExec(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	exe := libpf.Intern("/bin/foobar")

	// The state each call was handed, which is how the exec handling is observable.
	var seen []any
	enricher := &testResourceEnricher{
		enrich: func(req *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			seen = append(seen, *req.State)
			*req.State = call
			return nil, false
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	// Seed a known process with a mapping the sync below can match and reuse, which
	// keeps it out of the ELF-parsing path that needs a fuller ProcessManager.
	rawMapping := process.RawMapping{
		Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
		Device: 7, Inode: 8, Path: exe.String(),
	}
	pm.pidToProcessInfo[pid] = &processInfo{
		meta: process.Meta{Executable: exe},
		mappings: []Mapping{{
			Vaddr:  libpf.Address(rawMapping.Vaddr),
			Length: rawMapping.Length,
			Device: rawMapping.Device,
			Inode:  rawMapping.Inode,
			FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
				File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
					FileID:   libpf.NewFileID(1, 0),
					FileName: libpf.Intern("foobar"),
				}),
				Start: 0,
				End:   libpf.Address(rawMapping.Length),
			}),
		}},
		contributions: make([]*pcommon.Resource, 1),
		enricherState: make([]any, 1),
	}

	// Known process, unchanged executable: what the previous call stored is still
	// there, the seeded record included.
	proc := &testProcess{pid: pid, exe: exe, mappings: []process.RawMapping{rawMapping}}
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	require.Equal([]any{nil, 1}, seen)

	// Executable changed: the state derived from the program that is gone goes too.
	pm.SynchronizeProcess(&testProcess{
		pid: pid, exe: libpf.Intern("/bin/other"),
		mappings: []process.RawMapping{rawMapping},
	})
	require.Equal([]any{nil, 1, nil}, seen)
}

// TestSynchronizeProcessResourceEnricherStateKeptWithoutMappings verifies that a
// process retaining no mapping keeps its derived state all the same. Retained
// mappings say nothing about the lifecycle — a fully JIT-compiled process keeps
// none — and looking execed every sync would resolve fill-once enrichers forever.
func TestSynchronizeProcessResourceEnricherStateKeptWithoutMappings(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	exe := libpf.Intern("/bin/foobar")

	var seen []any
	enricher := &testResourceEnricher{
		enrich: func(req *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			seen = append(seen, *req.State)
			*req.State = call
			return nil, false
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	// Non-executable, so no mapping is retained for the process.
	proc := &testProcess{pid: pid, exe: exe, mappings: []process.RawMapping{{
		Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R,
		Device: 7, Inode: 8, Path: exe.String(),
	}}}

	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)

	pm.mu.RLock()
	mappings := pm.pidToProcessInfo[pid].mappings
	pm.mu.RUnlock()
	require.Empty(mappings)

	// New once, on first observation, and never again.
	require.Equal([]any{nil, 1, 2}, seen)
}

// TestSynchronizeProcessResourceEnricherExecDropsContributions verifies that an exec
// drops what the enrichers derived from the previous program. Otherwise an enricher
// resolving nothing for the new executable — runtime info once a Python process
// execs a native binary — would keep the old attributes indefinitely.
func TestSynchronizeProcessResourceEnricherExecDropsContributions(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	enricher := &testResourceEnricher{
		enrich: func(req *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			if call == 1 {
				*req.State = "resolved"
				return resourceWithAttr("process.runtime.name", "cpython"), true
			}
			// Nothing to report for the new executable.
			return nil, false
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("/usr/bin/python3")})
	_, resource := pm.metaForPID(pid)
	require.Equal(map[string]string{"process.runtime.name": "cpython"}, resourceAttrs(resource))

	// Exec: the contribution and the state derived from the old program go.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("/usr/bin/native")})
	_, resource = pm.metaForPID(pid)
	require.Nil(resource)
	require.Nil(*enricher.reqs[1].State)
}

// TestSynchronizeProcessExecDoesNotPairNewMetaWithOldResource verifies that a
// replaced program's resource is never readable beside the new executable's
// metadata, which is published before the enrichers run and the resource after. An
// enricher runs in exactly that window, so it can observe what a trace would see.
func TestSynchronizeProcessExecDoesNotPairNewMetaWithOldResource(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	type observation struct {
		exe      string
		resource *pcommon.Resource
	}
	var observed []observation

	enricher := &testResourceEnricher{}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})
	enricher.enrich = func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
		meta, resource := pm.metaForPID(pid)
		observed = append(observed, observation{meta.Executable.String(), resource})
		// Identify the program, so a contribution carried across the exec shows up.
		return resourceWithAttr("exe", meta.Executable.String()), true
	}

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("/usr/bin/python3")})
	_, resource := pm.metaForPID(pid)
	require.Equal(map[string]string{"exe": "/usr/bin/python3"}, resourceAttrs(resource))

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("/usr/bin/native")})
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"exe": "/usr/bin/native"}, resourceAttrs(resource))

	require.Len(observed, 2)
	// First observation: the process has no resource yet.
	require.Equal("/usr/bin/python3", observed[0].exe)
	require.Nil(observed[0].resource)
	// Second: metadata is already the new program's, so the old resource is gone.
	require.Equal("/usr/bin/native", observed[1].exe)
	require.Nil(observed[1].resource)
}

// TestSynchronizeProcessMergesResourceContributions verifies that contributions
// from several enrichers are merged, with later enrichers winning on key
// collisions, and that each enricher's contribution is tracked independently.
func TestSynchronizeProcessMergesResourceContributions(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	first := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
			r := pcommon.NewResource()
			r.Attributes().PutStr("shared", "first")
			r.Attributes().PutStr("only.first", "1")
			return &r, true
		},
	}
	second := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			// Contribute only on the first call, to check the stored contribution
			// still takes part in later merges.
			if call > 1 {
				return nil, false
			}
			return resourceWithAttr("shared", "second"), true
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{first, second})

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource := pm.metaForPID(pid)
	require.Equal(map[string]string{"shared": "second", "only.first": "1"},
		resourceAttrs(resource))

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"shared": "second", "only.first": "1"},
		resourceAttrs(resource))
}

// TestSynchronizeProcessResourceEnricherState verifies that per-process enricher
// state survives across synchronizations and is dropped, and closed, on exit.
func TestSynchronizeProcessResourceEnricherState(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	var seen []int
	enricher := &testResourceEnricher{
		enrich: func(req *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
			state, _ := (*req.State).(*testEnricherState)
			if state == nil {
				state = &testEnricherState{}
				*req.State = state
			}
			state.counter++
			seen = append(seen, state.counter)
			return nil, false
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	proc := &testProcess{pid: pid, exe: libpf.Intern("foobar")}
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	require.Equal([]int{1, 2, 3}, seen)

	pm.mu.RLock()
	state, _ := pm.pidToProcessInfo[pid].enricherState[0].(*testEnricherState)
	pm.mu.RUnlock()
	require.NotNil(state)

	// Process exit drops the state along with the processInfo holding it.
	pm.processPIDExit(pid)
	pm.ProcessedUntil(times.GetKTime())

	pm.mu.RLock()
	_, tracked := pm.pidToProcessInfo[pid]
	pm.mu.RUnlock()
	require.False(tracked)

	// A process observed again under the same PID starts from empty state.
	pm.SynchronizeProcess(proc)
	require.Equal([]int{1, 2, 3, 1}, seen)
}

type testEnricherState struct {
	counter int
}

// TestSynchronizeProcessResourceEnricherMappings verifies that only the mappings
// an enricher's WantMapping filter selects are delivered to it, and that each
// enricher gets its own selection.
func TestSynchronizeProcessResourceEnricherMappings(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	wantsNamed := &testResourceEnricher{
		cfg: procmeta.ResourceConfig{
			WantMapping: func(m *process.RawMapping) bool { return m.Path == "[anon:MY_REGION]" },
		},
	}
	wantsNothing := &testResourceEnricher{}
	pm := newTestProcessManager(nil,
		[]procmeta.ResourceEnricher{wantsNamed, wantsNothing})

	pm.SynchronizeProcess(&testProcess{
		pid: pid,
		exe: libpf.Intern("foobar"),
		mappings: []process.RawMapping{
			{Vaddr: 0x1000, Flags: elf.PF_R, Path: "/bin/foobar"},
			{Vaddr: 0x2000, Flags: elf.PF_R | elf.PF_W, Path: "[anon:MY_REGION]"},
			{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_W},
		},
	})

	require.Len(wantsNamed.reqs, 1)
	require.Equal([]process.RawMapping{
		{Vaddr: 0x2000, Flags: elf.PF_R | elf.PF_W, Path: "[anon:MY_REGION]"},
	}, wantsNamed.reqs[0].Mappings)

	require.Len(wantsNothing.reqs, 1)
	require.Empty(wantsNothing.reqs[0].Mappings)
}
