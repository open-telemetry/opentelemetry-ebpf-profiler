/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package processmanager

// See also utils/coredump/coredump_test.go for core dump based testing.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/process"
	"github.com/elastic/otel-profiling-agent/libpf/remotememory"
	"github.com/elastic/otel-profiling-agent/libpf/traceutil"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/metrics"
	pmebpf "github.com/elastic/otel-profiling-agent/processmanager/ebpf"
)

// dummyProcess implements pfelf.Process for testing purposes
type dummyProcess struct {
	pid libpf.PID
}

func (d *dummyProcess) PID() libpf.PID {
	return d.pid
}

func (d *dummyProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (d *dummyProcess) GetMappings() ([]process.Mapping, error) {
	return nil, errors.New("not implemented")
}

func (d *dummyProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (d *dummyProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (d *dummyProcess) GetMappingFile(_ *process.Mapping) string {
	return ""
}

func (d *dummyProcess) CalculateMappingFileID(m *process.Mapping) (libpf.FileID, error) {
	return pfelf.CalculateID(m.Path)
}

func (d *dummyProcess) OpenMappingFile(m *process.Mapping) (process.ReadAtCloser, error) {
	return os.Open(m.Path)
}

func (d *dummyProcess) OpenELF(name string) (*pfelf.File, error) {
	return pfelf.Open(name)
}

func (d *dummyProcess) Close() error {
	return nil
}

func newTestProcess(pid libpf.PID) process.Process {
	return &dummyProcess{pid: pid}
}

// dummyStackDeltaProvider is an implementation of nativeunwind.StackDeltaProvider.
// It is intended to be used only within this test.
type dummyStackDeltaProvider struct{}

// GetIntervalStructuresForFile fills in the expected data structure with semi random data.
func (d *dummyStackDeltaProvider) GetIntervalStructuresForFile(_ host.FileID,
	_ *pfelf.Reference, result *sdtypes.IntervalData) error {
	// nolint:gosec
	r := rand.New(rand.NewSource(42))
	addr := 0x10
	// nolint:gosec
	for i := 0; i < r.Intn(42); i++ {
		// nolint:gosec
		addr += r.Intn(42 * 42)
		// nolint:gosec
		data := int32(8 * r.Intn(42))
		result.Deltas.Add(sdtypes.StackDelta{
			Address: uint64(addr),
			Info:    sdtypes.UnwindInfo{Opcode: sdtypes.UnwindOpcodeBaseSP, Param: data},
		})
	}
	return nil
}

// GetAndResetStatistics satisfies the interface and does not return values.
func (d *dummyStackDeltaProvider) GetAndResetStatistics() nativeunwind.Statistics {
	return nativeunwind.Statistics{}
}

// Compile time check that the dummyStackDeltaProvider implements its interface correctly.
var _ nativeunwind.StackDeltaProvider = (*dummyStackDeltaProvider)(nil)

// generateDummyFiles creates num temporary files. The caller is responsible to delete
// these files afterwards.
func generateDummyFiles(t *testing.T, num int) []string {
	t.Helper()
	var files []string

	for i := 0; i < num; i++ {
		name := fmt.Sprintf("dummy%d", i)
		tmpfile, err := os.CreateTemp("", "*"+name)
		if err != nil {
			t.Fatalf("Failed to create dummy file %s: %v", name, err)
		}
		// The generated fileID is based on the content of the file.
		// So we write the pseudo random name to the file as content.
		content := []byte(tmpfile.Name())
		if _, err := tmpfile.Write(content); err != nil {
			t.Fatalf("Failed to write dummy content to file: %v", err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatalf("Failed to close temporary file: %v", err)
		}
		files = append(files, tmpfile.Name())
	}
	return files
}

// mappingArgs provides a structured way for the arguments to NewMapping()
// for the tests.
type mappingArgs struct {
	// pid represents the simulated process ID.
	pid libpf.PID
	// vaddr represents the simulated start of the mapped memory.
	vaddr uint64
	// bias is the load bias to simulate and verify.
	bias uint64
}

// ebpfMapsMockup implements the ebpf interface as test mockup
type ebpfMapsMockup struct {
	updateProcCount, deleteProcCount uint8

	stackDeltaMemory []pmebpf.StackDeltaEBPF
	// deleteStackDeltaRangesCount reflects the number of times
	// the deleteStackDeltaRanges to update the eBPF map was called.
	deleteStackDeltaRangesCount uint8
	// deleteStackDeltaPage reflects the number of times
	// the DeleteStackDeltaPage to update the eBPF map was called.
	deleteStackDeltaPage uint8
	// deletePidPageMappingCount reflects the number of times
	// the deletePidPageMapping to update the eBPF map was called.
	deletePidPageMappingCount uint8
	// expectedBias value for updatedPidPageToExeIDOffset calls
	expectedBias uint64
}

var _ interpreter.EbpfHandler = &ebpfMapsMockup{}

func (mockup *ebpfMapsMockup) RemoveReportedPID(libpf.PID) {
}

func (mockup *ebpfMapsMockup) UpdateInterpreterOffsets(uint16, host.FileID, []libpf.Range) error {
	return nil
}

func (mockup *ebpfMapsMockup) UpdateProcData(libpf.InterpType, libpf.PID, unsafe.Pointer) error {
	mockup.updateProcCount++
	return nil
}

func (mockup *ebpfMapsMockup) DeleteProcData(libpf.InterpType, libpf.PID) error {
	mockup.deleteProcCount++
	return nil
}

func (mockup *ebpfMapsMockup) UpdatePidInterpreterMapping(libpf.PID,
	lpm.Prefix, uint8, host.FileID, uint64) error {
	return nil
}

func (mockup *ebpfMapsMockup) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error {
	return nil
}

func (mockup *ebpfMapsMockup) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error { return nil }

func (mockup *ebpfMapsMockup) UpdateExeIDToStackDeltas(fileID host.FileID,
	deltaArrays []pmebpf.StackDeltaEBPF) (uint16, error) {
	mockup.stackDeltaMemory = append(mockup.stackDeltaMemory, deltaArrays...)
	// execinfomanager expects a mapID >0. So to fake this behavior, we return
	// parts of the fileID.
	return uint16(fileID), nil
}

func (mockup *ebpfMapsMockup) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	mockup.deleteStackDeltaRangesCount++
	return nil
}

func (mockup *ebpfMapsMockup) UpdateStackDeltaPages(host.FileID, []uint16,
	uint16, uint64) error {
	return nil
}

func (mockup *ebpfMapsMockup) DeleteStackDeltaPage(host.FileID, uint64) error {
	mockup.deleteStackDeltaPage++
	return nil
}

func (mockup *ebpfMapsMockup) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix,
	fileID uint64, bias uint64) error {
	if prefix.Key == 0 && fileID == 0 && bias == 0 {
		// If all provided values are 0 the hook was called to create
		// a dummy entry.
		return nil
	}
	if bias != mockup.expectedBias {
		return fmt.Errorf("expected bias 0x%x for PID %d but got 0x%x",
			mockup.expectedBias, pid, bias)
	}
	return nil
}

func (mockup *ebpfMapsMockup) setExpectedBias(expected uint64) {
	mockup.expectedBias = expected
}

func (mockup *ebpfMapsMockup) DeletePidPageMappingInfo(_ libpf.PID, prefixes []lpm.Prefix) (int,
	error) {
	mockup.deletePidPageMappingCount += uint8(len(prefixes))
	return len(prefixes), nil
}

func (mockup *ebpfMapsMockup) CollectMetrics() []metrics.Metric     { return []metrics.Metric{} }
func (mockup *ebpfMapsMockup) SupportsGenericBatchOperations() bool { return false }
func (mockup *ebpfMapsMockup) SupportsLPMTrieBatchOperations() bool { return false }

func TestInterpreterConvertTrace(t *testing.T) {
	partialNativeFrameFileID := uint64(0xabcdbeef)
	nativeFrameLineno := libpf.AddressOrLineno(0x1234)
	pythonAndNativeTrace := &host.Trace{
		Frames: []host.Frame{{
			// This represents a native frame
			File:   host.FileID(partialNativeFrameFileID),
			Lineno: nativeFrameLineno,
			Type:   libpf.NativeFrame,
		}, {
			File:   host.FileID(42),
			Lineno: libpf.AddressOrLineno(0x13e1bb8e), // same as runForeverTrace
			Type:   libpf.PythonFrame,
		}},
	}

	tests := map[string]struct {
		trace  *host.Trace
		expect *libpf.Trace
	}{
		"Convert Trace": {
			trace: pythonAndNativeTrace,
			expect: getExpectedTrace(pythonAndNativeTrace,
				[]libpf.AddressOrLineno{0, 1}),
		},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			mapper := NewMapFileIDMapper()
			for i := range testcase.trace.Frames {
				mapper.Set(testcase.trace.Frames[i].File, testcase.expect.Files[i])
			}

			interpreters := make([]bool, config.MaxTracers)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// To test ConvertTrace we do not require all parts of processmanager.
			manager, err := New(ctx,
				interpreters,
				1*time.Second,
				nil,
				nil,
				nil,
				nil,
				true)
			if err != nil {
				t.Fatalf("Failed to initialize new process manager: %v", err)
			}

			newTrace := manager.ConvertTrace(testcase.trace)

			testcase.expect.Hash = traceutil.HashTrace(testcase.expect)
			if (!reflect.DeepEqual(testcase.expect.Linenos, newTrace.Linenos) ||
				!reflect.DeepEqual(testcase.expect.Files, newTrace.Files)) &&
				testcase.expect.Hash == newTrace.Hash {
				t.Fatalf("Trace %v does not match expected trace %v", newTrace, testcase.expect)
			}
		})
	}
}

// getExpectedTrace returns a new libpf trace that is based on the provided host trace, but
// with the linenos replaced by the provided values. This function is for generating an expected
// trace for tests below.
func getExpectedTrace(origTrace *host.Trace, linenos []libpf.AddressOrLineno) *libpf.Trace {
	newTrace := &libpf.Trace{
		Hash: libpf.NewTraceHash(uint64(origTrace.Hash), uint64(origTrace.Hash)),
	}

	for _, frame := range origTrace.Frames {
		newTrace.Files = append(newTrace.Files, libpf.NewFileID(uint64(frame.File), 0))
		newTrace.FrameTypes = append(newTrace.FrameTypes, frame.Type)
		if linenos == nil {
			newTrace.Linenos = append(newTrace.Linenos, frame.Lineno)
		}
	}
	if linenos != nil {
		newTrace.Linenos = linenos
	}

	return newTrace
}

func TestNewMapping(t *testing.T) {
	tests := map[string]struct {
		// newMapping holds the arguments that are passed to NewMapping() in the test.
		// For each mappingArgs{} a temporary file will be created.
		newMapping []mappingArgs
		// duplicate indicates if for each {}mappingArgs the generated dummy file
		// should be loaded twice to simulate a duplicate loading.
		duplicate bool
		// expectedStackDeltas holds the number of stack deltas that are
		// expected after loading all temporary files with the arguments from newMapping.
		expectedStackDeltas int
	}{
		"regular load": {newMapping: []mappingArgs{
			{pid: 1, vaddr: 0x10000, bias: 0x0000},
			{pid: 2, vaddr: 0x40000, bias: 0x2000},
			{pid: 3, vaddr: 0x60000, bias: 0x3000},
			{pid: 4, vaddr: 0x40000, bias: 0x4000}},
			expectedStackDeltas: 28},
		"duplicate load": {newMapping: []mappingArgs{
			{pid: 123, vaddr: 0x0F000, bias: 0x1000},
			{pid: 456, vaddr: 0x50000, bias: 0x4000},
			{pid: 789, vaddr: 0x40000, bias: 0}},
			duplicate:           true,
			expectedStackDeltas: 21},
	}

	cacheDir, err := os.MkdirTemp("", "*_cacheDir")
	if err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	defer os.RemoveAll(cacheDir)

	if err = config.SetConfiguration(&config.Config{
		ProjectID:      42,
		CacheDirectory: cacheDir,
		SecretToken:    "secret"}); err != nil {
		t.Fatalf("failed to set temporary config: %s", err)
	}

	for name, testcase := range tests {
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			// The generated dummy files do not contain valid stack deltas,
			// so we replace the stack delta provider.
			dummyProvider := dummyStackDeltaProvider{}
			ebpfMockup := &ebpfMapsMockup{}

			// For this test do not include interpreters.
			noInterpreters := make([]bool, config.MaxTracers)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			manager, err := New(ctx,
				noInterpreters,
				1*time.Second,
				ebpfMockup,
				NewMapFileIDMapper(),
				nil,
				&dummyProvider,
				true)
			if err != nil {
				t.Fatalf("Failed to initialize new process manager: %v", err)
			}

			// Replace the internal hooks for the tests. These hooks catch the
			// updates of the eBPF maps and let us compare the results.
			manager.metricsAddSlice = func(m []metrics.Metric) {
				for id, value := range m {
					t.Logf("Added +%d to metric %d\n", value, id)
				}
			}

			execs := generateDummyFiles(t, len(testcase.newMapping))
			defer func() {
				for _, exe := range execs {
					os.Remove(exe)
				}
			}()

			if testcase.duplicate {
				execs = append(execs, execs...)
			}

			// For the duplicate test case we have more test files than provided
			// arguments to NewMapping(). modulo makes sure we don't exceed the
			// index of the provided arguments to NewMapping().
			modulo := len(testcase.newMapping)

			// Simulate new memory mappings
			for index, exec := range execs {
				pid := testcase.newMapping[index%modulo].pid
				vaddr := libpf.Address(testcase.newMapping[index%modulo].vaddr)
				bias := testcase.newMapping[index%modulo].bias
				ebpfMockup.setExpectedBias(bias)

				pr := newTestProcess(pid)
				elfRef := pfelf.NewReference(exec, pr)
				err := manager.handleNewMapping(
					pr, &Mapping{
						FileID: host.FileID(index % modulo),
						Vaddr:  vaddr,
						Bias:   bias,
						Length: 0x10,
					}, elfRef)
				elfRef.Close()
				if err != nil {
					t.Fatalf("Failed to add new mapping: %v", err)
				}
			}

			if len(ebpfMockup.stackDeltaMemory) != testcase.expectedStackDeltas {
				t.Fatalf("Expected %d entries in big_stack_deltas but got %d",
					testcase.expectedStackDeltas,
					len(ebpfMockup.stackDeltaMemory))
			}
		})
	}
}

// populateManager fills the internal maps of the process manager with some dummy information.
func populateManager(t *testing.T, pm *ProcessManager) {
	t.Helper()

	data := []struct {
		pid libpf.PID

		mapping Mapping
	}{
		{
			pid: 1,
			mapping: Mapping{
				FileID: host.FileID(127),
				Vaddr:  libpf.Address(0x1000),
				Bias:   0x1000,
				Length: 127,
			},
		}, {
			pid: 2,
			mapping: Mapping{
				FileID: host.FileID(128),
				Vaddr:  libpf.Address(0x1000),
				Bias:   0x1000,
				Length: 128,
			},
		}, {
			pid: 2,
			mapping: Mapping{
				FileID: host.FileID(129),
				Vaddr:  libpf.Address(0x1000),
				Bias:   0x1000,
				Length: 129,
			},
		}, {
			pid: 920,
			mapping: Mapping{
				FileID: host.FileID(128),
				Vaddr:  libpf.Address(0x1000),
				Bias:   0x1000,
				Length: 128,
			},
		}, {
			pid: 921,
			mapping: Mapping{
				FileID: host.FileID(129),
				Vaddr:  libpf.Address(0x2000),
				Bias:   0x2000,
				Length: 129,
			},
		}, {
			pid: 3,
			mapping: Mapping{
				FileID: host.FileID(130),
				Vaddr:  libpf.Address(0x3000),
				Bias:   0x3000,
				Length: 130,
			},
		}, {
			pid: 3,
			mapping: Mapping{
				FileID: host.FileID(131),
				Vaddr:  libpf.Address(0x4000),
				Bias:   0x4000,
				Length: 131,
			},
		},
	}

	mockup := pm.ebpf.(*ebpfMapsMockup)

	for _, d := range data {
		c := d
		mockup.setExpectedBias(c.mapping.Bias)
		pr := newTestProcess(c.pid)
		elfRef := pfelf.NewReference("", pr)
		if err := pm.handleNewMapping(pr, &c.mapping, elfRef); err != nil {
			t.Fatalf("Failed to populate manager with process: %v", err)
		}
	}
}

func TestProcExit(t *testing.T) {
	tests := map[string]struct {
		// pid represents the ID of a process.
		pid libpf.PID
		// deletePidPageMappingCount reflects the number of times
		// the deletePidPageMappingHook to update the eBPF map was called.
		deletePidPageMappingCount uint8
		// deleteExeIDToIndicesCount reflects the number of times
		// the deleteExeIDToIndicesHook to update the eBPF map was called.
		deleteExeIDToIndicesCount uint8
		// deleteStackDeltaRangesCount reflects the number of times
		// the deleteStackDeltaRangesHook to update the eBPF map was called.
		deleteStackDeltaRangesCount uint8
	}{
		// unknown process simulates a test case where the process manager is
		// informed about the process exit of a process it is not aware of.
		"unknown process": {pid: 512},
		// process with single mapping simulates a test case where a process with a single
		// memory mapping exits and this was the last mapping for the loaded executables.
		"process with single mapping": {pid: 1,
			deletePidPageMappingCount:   8,
			deleteExeIDToIndicesCount:   1,
			deleteStackDeltaRangesCount: 1},
		// process with multiple mapped mappings simulates a test case where a process with
		// multiple memory mappings exits but the mappings are still referenced else where.
		"process with multiple mapped mappings": {pid: 2,
			deletePidPageMappingCount:   3,
			deleteExeIDToIndicesCount:   0,
			deleteStackDeltaRangesCount: 0},
		// process with multiple one-time mappings simulates a test case where a process with
		// multiple one-time memory mappings exits and these mappings need to be removed.
		"process with multiple one-time mappings": {pid: 3,
			deletePidPageMappingCount:   6,
			deleteExeIDToIndicesCount:   2,
			deleteStackDeltaRangesCount: 2},
	}

	for name, testcase := range tests {
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			// The generated dummy files do not contain valid stack deltas,
			// so we replace the stack delta provider.
			dummyProvider := dummyStackDeltaProvider{}
			ebpfMockup := &ebpfMapsMockup{}

			// For this test do not include interpreters.
			noInterpreters := make([]bool, config.MaxTracers)

			ctx, cancel := context.WithCancel(context.Background())

			manager, err := New(ctx,
				noInterpreters,
				1*time.Second,
				ebpfMockup,
				NewMapFileIDMapper(),
				nil,
				&dummyProvider,
				true)
			if err != nil {
				t.Fatalf("Failed to initialize new process manager: %v", err)
			}
			defer cancel()

			// Replace the internal hooks for the tests. These hooks catch the
			// updates of the eBPF maps and let us compare the results.
			manager.metricsAddSlice = func(m []metrics.Metric) {
				for id, value := range m {
					t.Logf("Added +%d to metric %d\n", value, id)
				}
			}

			populateManager(t, manager)

			_ = manager.ProcessPIDExit(testcase.pid)
			if testcase.deletePidPageMappingCount != ebpfMockup.deletePidPageMappingCount {
				t.Fatalf("Calls of deletePidPageMappingHook. Expected: %d\tGot: %d",
					testcase.deletePidPageMappingCount,
					ebpfMockup.deletePidPageMappingCount)
			}

			if testcase.deleteStackDeltaRangesCount != ebpfMockup.deleteStackDeltaPage {
				t.Fatalf("Calls of DeleteStackDeltaPage. Expected: %d\tGot: %d",
					testcase.deleteStackDeltaRangesCount,
					ebpfMockup.deleteStackDeltaPage)
			}

			if testcase.deleteStackDeltaRangesCount != ebpfMockup.deleteStackDeltaRangesCount {
				t.Fatalf("Calls of deleteStackDeltaRangesCountHook. Expected: %d\tGot: %d",
					testcase.deleteStackDeltaRangesCount,
					ebpfMockup.deleteStackDeltaRangesCount)
			}
		})
	}
}
