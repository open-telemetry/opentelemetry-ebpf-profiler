// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pacmask"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// sysConfigVars supports collecting system configuration information.
type sysConfigVars struct {
	tpbase_offset       uint64
	task_stack_offset   uint32
	stack_ptregs_offset uint32

	// Offsets and sizes for translating kernel-root PIDs (emitted by eBPF
	// helpers) to PIDs in the profiler's own PID namespace (the view its /proc
	// uses). See the matching `extern` declarations in support/ebpf/bpfdefs.h.
	task_thread_pid_offset   uint32
	task_group_leader_offset uint32
	pid_level_offset         uint32
	pid_numbers_offset       uint32
	upid_size                uint32
	upid_nr_offset           uint32

	// profiler_pidns_level is the depth of the profiler's own PID namespace in
	// the kernel hierarchy. Discovered at startup via read_pid_level; 0 when
	// the profiler runs in the init PID namespace.
	profiler_pidns_level uint32
}

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

// memberByName resolves btf Member from a Struct with given name
func memberByName(t *btf.Struct, field string) (*btf.Member, error) {
	for i, m := range t.Members {
		if m.Name == field {
			return &t.Members[i], nil
		}
	}
	return nil, fmt.Errorf("member '%s' not found", field)
}

// calculateFieldOffset calculates the offset for given fieldSpec which
// can refer to field within nested structs.
func calculateFieldOffset(t btf.Type, fieldSpec string) (uint, error) {
	offset := uint(0)
	for field := range strings.SplitSeq(fieldSpec, ".") {
		st, ok := t.(*btf.Struct)
		if !ok {
			return 0, fmt.Errorf("field '%s' is not a struct", field)
		}

		member, err := memberByName(st, field)
		if err != nil {
			return 0, err
		}
		offset += uint(member.Offset.Bytes())
		t = member.Type
	}
	return offset, nil
}

// getTSDBaseFieldSpec returns the architecture specific name of the `task_struct`
// member that contains base address for thread specific data.
func getTSDBaseFieldSpec() string {
	//nolint:goconst
	switch runtime.GOARCH {
	case "amd64":
		return "thread.fsbase"
	case "arm64":
		return "thread.uw.tp_value"
	default:
		panic("not supported")
	}
}

// parseBTF resolves the SystemConfig data from kernel BTF
func parseBTF(vars *sysConfigVars) error {
	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	defer fh.Close()

	spec, err := btf.LoadSplitSpecFromReader(fh, nil)
	if err != nil {
		return err
	}

	var taskStruct *btf.Struct
	err = spec.TypeByName("task_struct", &taskStruct)
	if err != nil {
		return err
	}

	stackOffset, err := calculateFieldOffset(taskStruct, "stack")
	if err != nil {
		return err
	}
	vars.task_stack_offset = uint32(stackOffset)

	tpbaseOffset, err := calculateFieldOffset(taskStruct, getTSDBaseFieldSpec())
	if err != nil {
		return err
	}
	vars.tpbase_offset = uint64(tpbaseOffset)

	// Best-effort: populate offsets used to translate eBPF kernel-root PIDs
	// into the profiler's own pidns. Failure leaves offsets at 0 and the BPF
	// helpers fall back to the kernel-root path.
	parsePidStructLayout(spec, taskStruct, vars)
	return nil
}

// parsePidStructLayout best-effort populates the task_struct/pid/upid offsets
// used by the BPF helpers to translate kernel-root PIDs to PIDs in the
// profiler's own pidns. Returns true on success. On failure (kernels older
// than 4.19, which lack task_struct.thread_pid) returns false; the caller
// then leaves profiler_pidns_level == 0 and the BPF helpers short-circuit to
// the existing kernel-root behavior — i.e., we preserve the pre-fix path on
// kernels where this fix cannot apply.
func parsePidStructLayout(spec *btf.Spec, taskStruct *btf.Struct,
	vars *sysConfigVars,
) bool {
	threadPidOff, err := calculateFieldOffset(taskStruct, "thread_pid")
	if err != nil {
		log.Infof("PID-ns translation disabled: task_struct.thread_pid missing (kernel < 4.19?): %v", err)
		return false
	}
	groupLeaderOff, err := calculateFieldOffset(taskStruct, "group_leader")
	if err != nil {
		log.Infof("PID-ns translation disabled: task_struct.group_leader missing: %v", err)
		return false
	}
	var pidStruct *btf.Struct
	if err = spec.TypeByName("pid", &pidStruct); err != nil {
		log.Infof("PID-ns translation disabled: struct pid not in BTF: %v", err)
		return false
	}
	levelOff, err := calculateFieldOffset(pidStruct, "level")
	if err != nil {
		log.Infof("PID-ns translation disabled: struct pid.level missing: %v", err)
		return false
	}
	numbersOff, err := calculateFieldOffset(pidStruct, "numbers")
	if err != nil {
		log.Infof("PID-ns translation disabled: struct pid.numbers missing: %v", err)
		return false
	}
	var upidStruct *btf.Struct
	if err = spec.TypeByName("upid", &upidStruct); err != nil {
		log.Infof("PID-ns translation disabled: struct upid not in BTF: %v", err)
		return false
	}
	nrOff, err := calculateFieldOffset(upidStruct, "nr")
	if err != nil {
		log.Infof("PID-ns translation disabled: struct upid.nr missing: %v", err)
		return false
	}

	vars.task_thread_pid_offset = uint32(threadPidOff)
	vars.task_group_leader_offset = uint32(groupLeaderOff)
	vars.pid_level_offset = uint32(levelOff)
	vars.pid_numbers_offset = uint32(numbersOff)
	vars.upid_size = uint32(upidStruct.Size)
	vars.upid_nr_offset = uint32(nrOff)
	return true
}

// executeSystemAnalysisBpfCode will execute given analysis program with the address argument.
func executeSystemAnalysisBpfCode(progSpec *cebpf.ProgramSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	systemAnalysis := maps["system_analysis"]

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Pid:     uint32(os.Getpid()),
		Address: uint64(address),
	}

	if err = systemAnalysis.Update(unsafe.Pointer(&key0), unsafe.Pointer(&data),
		cebpf.UpdateAny); err != nil {
		return nil, 0, fmt.Errorf("failed to write system_analysis 0x%x: %v",
			address, err)
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	// Load a BPF program to load the function code in systemAnalysis.
	// It attaches to raw tracepoint of entering syscall and triggers
	// when running in our PID context.
	prog, err := cebpf.NewProgram(progSpec)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load read_kernel_function_or_task_struct: %v", err)
	}
	defer prog.Close()

	var progLink link.Link
	switch prog.Type() {
	case cebpf.RawTracepoint:
		progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: prog,
		})
	case cebpf.TracePoint:
		progLink, err = link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
	default:
		err = fmt.Errorf("invalid system analysis program type '%v'", prog.Type())
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to configure tracepoint: %v", err)
	}
	err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data))
	_ = progLink.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get analysis data: %v", err)
	}
	if err = validateSystemAnalysisResult(data, address); err != nil {
		return nil, 0, err
	}

	return data.Code[:], data.Address, nil
}

func validateSystemAnalysisResult(data support.SystemAnalysis, address libpf.SymbolValue) error {
	if data.Pid != 0 {
		return fmt.Errorf("%w for pid %d at 0x%x", errSystemAnalysisNotHandled, data.Pid, address)
	}

	if data.Err != 0 {
		if data.Err < 0 {
			return fmt.Errorf("%w at 0x%x: %w (helper err=%d)", errSystemAnalysisFailed, address, syscall.Errno(-data.Err), data.Err)
		}

		return fmt.Errorf("%w at 0x%x: helper err=%d", errSystemAnalysisFailed, address, data.Err)
	}

	return nil
}

// loadKernelCode will request the ebpf code to read the first X bytes from given address.
func loadKernelCode(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) ([]byte, error) {
	code, _, err := executeSystemAnalysisBpfCode(coll.Programs["read_kernel_memory"], maps, address)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct will request the ebpf code to read bytes from the given offset from
// the current task_struct.
func readTaskStruct(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	return executeSystemAnalysisBpfCode(coll.Programs["read_task_struct"], maps, address)
}

// determineStackPtregs determines the offset of `struct pt_regs` within the entry stack
// when the `stack` field offset within `task_struct` is already known.
func determineStackPtregs(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	vars *sysConfigVars,
) error {
	data, ptregs, err := readTaskStruct(coll, maps, libpf.SymbolValue(vars.task_stack_offset))
	if err != nil {
		return err
	}
	stackBase := binary.LittleEndian.Uint64(data)
	vars.stack_ptregs_offset = uint32(ptregs - stackBase)
	return nil
}

// determineStackLayout scans `task_struct` for offset of the `stack` field, and using
// its value determines the offset of `struct pt_regs` within the entry stack.
func determineStackLayout(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	vars *sysConfigVars,
) error {
	const maxTaskStructSize = 8 * 1024
	const maxStackSize = 64 * 1024

	pageSizeMinusOne := uint64(os.Getpagesize() - 1)

	for offs := 0; offs < maxTaskStructSize; {
		data, ptregs, err := readTaskStruct(coll, maps, libpf.SymbolValue(offs))
		if err != nil {
			return err
		}

		for i := 0; i < len(data); i += 8 {
			stackBase := binary.LittleEndian.Uint64(data[i:])
			// Stack base should be page aligned
			if stackBase&pageSizeMinusOne != 0 {
				continue
			}
			if ptregs > stackBase && ptregs < stackBase+maxStackSize {
				vars.task_stack_offset = uint32(offs + i)
				vars.stack_ptregs_offset = uint32(ptregs - stackBase)
				return nil
			}
		}
		offs += len(data)
	}
	return errors.New("unable to find task stack offset")
}

// applyVariablesToMap hydrates rodata MapSpec.Contents from VariableSpec.Value.
// cilium/ebpf's NewCollection does this internally via the unexported
// MapSpec.updateDataSection; loadAllMaps (used here so analysis sub-collection
// shares maps via FDs) does not, so we replicate it for the analysis path.
func applyVariablesToMap(spec *cebpf.CollectionSpec, sectionName string) error {
	mapSpec, ok := spec.Maps[sectionName]
	if !ok {
		return nil
	}
	if len(mapSpec.Contents) != 1 {
		return fmt.Errorf("rodata section %s: expected 1 KV entry, got %d", sectionName, len(mapSpec.Contents))
	}
	data, ok := mapSpec.Contents[0].Value.([]byte)
	if !ok {
		return fmt.Errorf("rodata section %s: Contents[0].Value is %T, not []byte", sectionName, mapSpec.Contents[0].Value)
	}
	// Contents may be shared with the original spec; clone before mutation.
	dataCopy := append([]byte(nil), data...)
	for _, vs := range spec.Variables {
		if vs.SectionName != sectionName || len(vs.Value) == 0 {
			continue
		}
		end := int(vs.Offset) + len(vs.Value)
		if end > len(dataCopy) {
			return fmt.Errorf("variable %s (offset %d size %d) exceeds rodata size %d",
				vs.Name, vs.Offset, len(vs.Value), len(dataCopy))
		}
		copy(dataCopy[vs.Offset:end], vs.Value)
	}
	mapSpec.Contents = []cebpf.MapKV{{Key: uint32(0), Value: dataCopy}}
	return nil
}

// prepareAnalysis creates a new CollectionSpec for the system analysis.
func prepareAnalysis(orig *cebpf.CollectionSpec) (*cebpf.CollectionSpec, map[string]*cebpf.Map, error) {
	new := &cebpf.CollectionSpec{
		Maps:      make(map[string]*cebpf.MapSpec),
		Programs:  make(map[string]*cebpf.ProgramSpec),
		Variables: make(map[string]*cebpf.VariableSpec),
	}
	new.Maps["system_analysis"] = orig.Maps["system_analysis"].Copy()
	new.Maps[".rodata.var"] = orig.Maps[".rodata.var"].Copy()
	if rodata, ok := orig.Maps[".rodata"]; ok {
		new.Maps[".rodata"] = rodata.Copy()
	}

	// Copy Variables so VariableSpec.Set() values applied to `orig` propagate,
	// then hydrate the rodata maps' Contents from those Variables.
	for name, vs := range orig.Variables {
		new.Variables[name] = vs.Copy()
	}
	if err := applyVariablesToMap(new, ".rodata.var"); err != nil {
		return nil, nil, fmt.Errorf("hydrate .rodata.var: %w", err)
	}
	if err := applyVariablesToMap(new, ".rodata"); err != nil {
		return nil, nil, fmt.Errorf("hydrate .rodata: %w", err)
	}

	new.Programs["read_kernel_memory"] = orig.Programs["read_kernel_memory"].Copy()
	new.Programs["read_task_struct"] = orig.Programs["read_task_struct"].Copy()
	new.Programs["read_pid_level"] = orig.Programs["read_pid_level"].Copy()

	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{}, maps); err != nil {
		return nil, nil, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	return new, maps, nil
}

func determineSysConfig(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kmod *kallsyms.Module, includeTracers types.IncludedTracers, vars *sysConfigVars,
) error {
	if err := parseBTF(vars); err != nil {
		log.Infof("Using binary analysis (BTF not available: %s)", err)

		if err = determineStackLayout(coll, maps, vars); err != nil {
			return err
		}

		if includeTracers.Has(types.PerlTracer) || includeTracers.Has(types.PythonTracer) ||
			includeTracers.Has(types.Labels) {
			var tpbaseOffset uint64
			tpbaseOffset, err = loadTPBaseOffset(coll, maps, kmod)
			if err != nil {
				return err
			}
			vars.tpbase_offset = tpbaseOffset
		}
	} else {
		// Sadly BTF does not currently include THREAD_SIZE which is needed
		// to calculate the offset of struct pt_regs in the entry stack.
		// The value also depends of some kernel configurations, so lets
		// analyze it dynamically for now.
		if err = determineStackPtregs(coll, maps, vars); err != nil {
			return err
		}
	}

	log.Infof("Found offsets: task stack %#x, pt_regs %#x, tpbase %#x",
		vars.task_stack_offset,
		vars.stack_ptregs_offset,
		vars.tpbase_offset)

	return nil
}

// loadRodataVars initializes RODATA variables for the eBPF programs.
func loadRodataVars(coll *cebpf.CollectionSpec, kmod *kallsyms.Module, cfg *Config) error {
	if cfg.VerboseMode {
		if err := coll.Variables["with_debug_output"].Set(uint32(1)); err != nil {
			return fmt.Errorf("failed to set debug output: %v", err)
		}
	}

	if err := coll.Variables["off_cpu_threshold"].Set(cfg.OffCPUThreshold); err != nil {
		return fmt.Errorf("failed to set off_cpu_threshold: %v", err)
	}

	if err := coll.Variables["filter_error_frames"].Set(cfg.FilterErrorFrames); err != nil {
		return fmt.Errorf("failed to set drop_error_only_traces: %v", err)
	}

	if err := coll.Variables["filter_idle_frames"].Set(cfg.FilterIdleFrames); err != nil {
		return fmt.Errorf("failed to set debug output: %v", err)
	}

	pacMask := pacmask.GetPACMask()
	if pacMask != 0 {
		log.Infof("Determined PAC mask to be 0x%016X", pacMask)
	} else {
		log.Debug("PAC is not enabled on the system.")
	}
	if err := coll.Variables["inverse_pac_mask"].Set(^pacMask); err != nil {
		return fmt.Errorf("failed to set inverse_pac_mask: %v", err)
	}

	rodataVars := sysConfigVars{}

	// Best-effort populate the task_struct/pid/upid offsets from BTF and push
	// them as rodata BEFORE prepareAnalysis, so the analysis filter that uses
	// these offsets sees them populated. If the offsets aren't available
	// (e.g., pre-4.19 kernel, or no BTF), we leave them at zero — the BPF
	// helpers short-circuit on profiler_pidns_level == 0 and fall back to
	// kernel-root behavior, matching the pre-fix path.
	if err := parseBTF(&rodataVars); err != nil {
		log.Infof("PID-ns translation disabled: BTF unavailable: %v", err)
	}
	if err := setPidLayoutVars(coll, &rodataVars); err != nil {
		return err
	}

	systemAnalysisColl, maps, err := prepareAnalysis(coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if err := determineSysConfig(systemAnalysisColl, maps, kmod, cfg.IncludeTracers, &rodataVars); err != nil {
		return fmt.Errorf("failed to determine system configs: %v", err)
	}

	// Discover the profiler's own PID-namespace level. Only meaningful when
	// the task-walking offsets are populated; otherwise we keep level=0 and
	// the BPF helpers stay on the kernel-root path.
	if rodataVars.task_thread_pid_offset != 0 {
		pidNsLevel, err := loadPidNsLevel(systemAnalysisColl, maps)
		if err != nil {
			return fmt.Errorf("failed to discover profiler PID namespace level: %v", err)
		}
		rodataVars.profiler_pidns_level = pidNsLevel
		log.Infof("Profiler PID namespace level: %d", pidNsLevel)
	}
	// read_pid_level is only used during startup — remove it from the main
	// collection so it doesn't get attached to every sys_enter for the
	// lifetime of the collector.
	delete(coll.Programs, "read_pid_level")

	if err := coll.Variables["tpbase_offset"].Set(rodataVars.tpbase_offset); err != nil {
		return fmt.Errorf("failed to set tpbase_offset: %v", err)
	}
	if err := coll.Variables["task_stack_offset"].Set(rodataVars.task_stack_offset); err != nil {
		return fmt.Errorf("failed to set task_stack_offset: %v", err)
	}
	if err := coll.Variables["stack_ptregs_offset"].Set(rodataVars.stack_ptregs_offset); err != nil {
		return fmt.Errorf("failed to set stack_ptregs_offset: %v", err)
	}
	if err := coll.Variables["profiler_pidns_level"].Set(rodataVars.profiler_pidns_level); err != nil {
		return fmt.Errorf("failed to set profiler_pidns_level: %v", err)
	}

	return nil
}

// setPidLayoutVars applies the PID-layout offsets to coll's rodata. Called
// before prepareAnalysis so the analysis sub-collection sees these values via
// the Variables copy in prepareAnalysis.
func setPidLayoutVars(coll *cebpf.CollectionSpec, vars *sysConfigVars) error {
	setters := []struct {
		name  string
		value uint32
	}{
		{"task_thread_pid_offset", vars.task_thread_pid_offset},
		{"task_group_leader_offset", vars.task_group_leader_offset},
		{"pid_level_offset", vars.pid_level_offset},
		{"pid_numbers_offset", vars.pid_numbers_offset},
		{"upid_size", vars.upid_size},
		{"upid_nr_offset", vars.upid_nr_offset},
	}
	for _, s := range setters {
		if err := coll.Variables[s.name].Set(s.value); err != nil {
			return fmt.Errorf("failed to set %s: %v", s.name, err)
		}
	}
	return nil
}

// loadPidNsLevel runs the read_pid_level analysis probe and returns the depth
// of the profiler's own PID namespace in the kernel hierarchy.
func loadPidNsLevel(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
) (uint32, error) {
	code, _, err := executeSystemAnalysisBpfCode(coll.Programs["read_pid_level"], maps, 0)
	if err != nil {
		return 0, fmt.Errorf("read_pid_level probe: %w", err)
	}
	if len(code) < 4 {
		return 0, fmt.Errorf("read_pid_level returned short result: %d bytes", len(code))
	}
	return binary.LittleEndian.Uint32(code[0:4]), nil
}
