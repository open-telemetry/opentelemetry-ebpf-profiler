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

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pacmask"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"golang.org/x/sys/unix"
)

// sysConfigVars supports collecting system configuration information.
type sysConfigVars struct {
	tpbase_offset       uint64
	task_stack_offset   uint32
	stack_ptregs_offset uint32
	vma_lookup_enabled  bool
	vma_vm_file_offset  uint32
	vma_vm_flags_offset uint32

	// Offsets and sizes for translating kernel-root PIDs (emitted by eBPF
	// helpers) to PIDs in the profiler's own PID namespace (the view its /proc
	// uses). See the matching extern declarations in support/ebpf/bpfdefs.h.
	task_thread_pid_offset   uint32
	task_group_leader_offset uint32
	pid_level_offset         uint32
	pid_numbers_offset       uint32
	upid_size                uint32
	upid_nr_offset           uint32

	// profiler_pidns_level is the depth of the profiler's own PID namespace in
	// the kernel hierarchy. Discovered at startup via read_pid_level; 0 when the
	// profiler runs in the initial PID namespace (translation is then a no-op).
	profiler_pidns_level uint32
}

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

func btfMembers(t btf.Type) ([]btf.Member, error) {
	switch typ := t.(type) {
	case *btf.Struct:
		return typ.Members, nil
	case *btf.Union:
		return typ.Members, nil
	default:
		return nil, fmt.Errorf("%s is not a struct or union", t.TypeName())
	}
}

func resolveBTFField(t btf.Type, field string) (uint, btf.Type, error) {
	members, err := btfMembers(t)
	if err != nil {
		return 0, nil, err
	}

	for _, member := range members {
		if member.Name == field {
			return uint(member.Offset.Bytes()), member.Type, nil
		}
	}

	for _, member := range members {
		if member.Name != "" {
			continue
		}
		offset, typ, err := resolveBTFField(member.Type, field)
		if err == nil {
			return uint(member.Offset.Bytes()) + offset, typ, nil
		}
	}

	return 0, nil, fmt.Errorf("member '%s' not found", field)
}

// calculateFieldOffset calculates the offset for given fieldSpec. Each path
// component may be nested in anonymous structs or unions.
func calculateFieldOffset(t btf.Type, fieldSpec string) (uint, error) {
	offset := uint(0)
	for field := range strings.SplitSeq(fieldSpec, ".") {
		fieldOffset, fieldType, err := resolveBTFField(t, field)
		if err != nil {
			return 0, err
		}
		offset += fieldOffset
		t = fieldType
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

func parseVMAOffsets(spec *btf.Spec, vars *sysConfigVars) {
	var vmaStruct *btf.Struct
	if err := spec.TypeByName("vm_area_struct", &vmaStruct); err != nil {
		log.Debugf("Unable to resolve vm_area_struct from BTF: %v", err)
		return
	}

	fileOffset, err := calculateFieldOffset(vmaStruct, "vm_file")
	if err != nil {
		log.Debugf("Unable to resolve vm_area_struct.vm_file from BTF: %v", err)
		return
	}

	flagsOffset, err := calculateFieldOffset(vmaStruct, "vm_flags")
	if err != nil {
		flagsOffset, err = calculateFieldOffset(vmaStruct, "__vm_flags")
		if err != nil {
			log.Debugf("Unable to resolve vm_area_struct vm_flags field from BTF: %v", err)
			return
		}
	}

	vars.vma_vm_file_offset = uint32(fileOffset)
	vars.vma_vm_flags_offset = uint32(flagsOffset)
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
	parseVMAOffsets(spec, vars)

	return nil
}

// parsePidStructLayout best-effort populates the task_struct/pid/upid offsets
// used by the BPF helpers to translate kernel-root PIDs to PIDs in the
// profiler's own pidns. Returns true on success. On failure (kernels older than
// 4.19, which lack task_struct.thread_pid, or missing BTF) it returns false and
// leaves the offsets at 0; the BPF helpers then short-circuit to the existing
// kernel-root behavior, preserving the pre-fix path where the fix cannot apply.
func parsePidStructLayout(vars *sysConfigVars) bool {
	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		log.Infof("PID-ns translation disabled: cannot open BTF: %v", err)
		return false
	}
	defer fh.Close()
	spec, err := btf.LoadSplitSpecFromReader(fh, nil)
	if err != nil {
		log.Infof("PID-ns translation disabled: cannot load BTF: %v", err)
		return false
	}

	var taskStruct *btf.Struct
	if err = spec.TypeByName("task_struct", &taskStruct); err != nil {
		log.Infof("PID-ns translation disabled: task_struct not in BTF: %v", err)
		return false
	}
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

// loadPidNsLevel runs the read_pid_level analysis probe and returns the depth of
// the profiler's own PID namespace in the kernel hierarchy (0 = initial ns).
func loadPidNsLevel(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map) (uint32, error) {
	code, _, err := executeSystemAnalysisBpfCode(coll.Programs["read_pid_level"], maps, 0)
	if err != nil {
		return 0, fmt.Errorf("read_pid_level probe: %w", err)
	}
	if len(code) < 4 {
		return 0, fmt.Errorf("read_pid_level returned short result: %d bytes", len(code))
	}
	return binary.LittleEndian.Uint32(code[0:4]), nil
}

// applyVariablesToMapSpec folds the collection's VariableSpec values into the
// Contents of the given data-section MapSpec (e.g. ".rodata.var"). cilium/ebpf
// performs this internally at NewCollection time via the unexported
// MapSpec.updateDataSection, but the system-analysis sub-collection is loaded
// with loadAllMaps (so it can share maps by FD), which does not. It is a no-op
// when the section does not exist or has no variables.
func applyVariablesToMapSpec(spec *cebpf.CollectionSpec, sectionName string) error {
	mapSpec, ok := spec.Maps[sectionName]
	if !ok {
		return nil
	}
	if len(mapSpec.Contents) != 1 {
		return fmt.Errorf("rodata section %s: expected 1 KV entry, got %d",
			sectionName, len(mapSpec.Contents))
	}
	data, ok := mapSpec.Contents[0].Value.([]byte)
	if !ok {
		return fmt.Errorf("rodata section %s: Contents[0].Value is %T, not []byte",
			sectionName, mapSpec.Contents[0].Value)
	}
	// Contents may share backing storage with the original spec; clone first.
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

	new.Programs["read_kernel_memory"] = orig.Programs["read_kernel_memory"].Copy()
	new.Programs["read_task_struct"] = orig.Programs["read_task_struct"].Copy()
	new.Programs["read_pid_level"] = orig.Programs["read_pid_level"].Copy()

	// The analysis probes consult the PID-layout rodata (via is_our_analysis_task),
	// but cilium/ebpf only folds VariableSpec values into a data-section map at
	// NewCollection time (via the unexported MapSpec.updateDataSection); this
	// sub-collection is built with loadAllMaps so it can share maps by FD, which
	// skips that step. Copy the Variables and fold their values into the rodata
	// maps here so the analysis probes observe the same offsets the main
	// collection does.
	for name, vs := range orig.Variables {
		new.Variables[name] = vs.Copy()
	}
	if err := applyVariablesToMapSpec(new, ".rodata.var"); err != nil {
		return nil, nil, fmt.Errorf("failed to apply variables to .rodata.var: %v", err)
	}
	if err := applyVariablesToMapSpec(new, ".rodata"); err != nil {
		return nil, nil, fmt.Errorf("failed to apply variables to .rodata: %v", err)
	}

	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{InterpretersConfig: interpreterconfig.AllInterpreters()}, maps); err != nil {
		return nil, nil, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	return new, maps, nil
}

func determineSysConfig(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kmod *kallsyms.Module, interpretersConfig interpreterconfig.Config, vars *sysConfigVars,
) error {
	if err := parseBTF(vars); err != nil {
		log.Infof("Using binary analysis (BTF not available: %s)", err)

		if err = determineStackLayout(coll, maps, vars); err != nil {
			return err
		}

		if !interpretersConfig.Perl.IsDisabled() || !interpretersConfig.Python.IsDisabled() ||
			!interpretersConfig.Go.IsLabelsDisabled() {
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

	log.Debugf("Found offsets: task stack %#x, pt_regs %#x, tpbase %#x, vma vm_file %#x, vma vm_flags %#x",
		vars.task_stack_offset,
		vars.stack_ptregs_offset,
		vars.tpbase_offset,
		vars.vma_vm_file_offset,
		vars.vma_vm_flags_offset)

	return nil
}

func configureVMALookup(coll *cebpf.CollectionSpec, cfg *Config, vars *sysConfigVars) {
	enabled, reason := probeVMALookupSupport(cfg)
	vars.vma_lookup_enabled = enabled
	if enabled {
		return
	}

	patched := disableVMAHelperCalls(coll)
	log.Infof("VMA lookup disabled: %s; patched %d instructions", reason, patched)
}

func probeVMALookupSupport(cfg *Config) (bool, string) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return false, fmt.Sprintf("failed to adjust rlimit for VMA helper probe: %v", err)
	}
	defer restoreRlimit()

	progTypes := []cebpf.ProgramType{cebpf.PerfEvent}
	if cfg.OffCPUThreshold > 0 || len(cfg.ProbeLinks) > 0 || cfg.LoadProbe {
		progTypes = append(progTypes, cebpf.Kprobe)
	}

	helpers := []asm.BuiltinFunc{asm.FnGetCurrentTaskBtf, asm.FnFindVma}
	for _, progType := range progTypes {
		for _, helper := range helpers {
			if err := features.HaveProgramHelper(progType, helper); err != nil {
				if errors.Is(err, cebpf.ErrNotSupported) {
					return false, fmt.Sprintf("%s is not supported for %s", helper, progType)
				}
				return false, fmt.Sprintf("failed to probe %s for %s: %v", helper, progType, err)
			}
		}
	}

	return true, ""
}

func disableVMAHelperCalls(coll *cebpf.CollectionSpec) int {
	patched := 0
	for _, progSpec := range coll.Programs {
		programPatched := false
		vmaCallbackPatched := false
		for i := range progSpec.Instructions {
			ins := &progSpec.Instructions[i]
			if ins.IsLoadOfFunctionPointer() && strings.HasPrefix(ins.Reference(), "find_vma_callback") {
				progSpec.Instructions[i] = asm.LoadImm(ins.Dst, 0, asm.DWord)
				patched++
				programPatched = true
				vmaCallbackPatched = true
				continue
			}
			if !ins.IsBuiltinCall() {
				continue
			}

			switch asm.BuiltinFunc(ins.Constant) {
			case asm.FnGetCurrentTaskBtf:
				// The VMA lookup path is disabled, so this helper should be unreachable.
				// Return NULL if it is reached anyway.
				progSpec.Instructions[i] = asm.Mov.Imm(asm.R0, 0).WithMetadata(ins.Metadata)
				patched++
				programPatched = true
			case asm.FnFindVma:
				// Older kernels reject programs that call unsupported helpers even when
				// the runtime branch is disabled. Return -ENOTSUP if reached so the
				// lookup is treated as unavailable, not as a successful lookup.
				progSpec.Instructions[i] = asm.Mov.Imm(asm.R0, -int32(unix.ENOTSUP)).
					WithMetadata(ins.Metadata)
				patched++
				programPatched = true
			}
		}
		if programPatched {
			if vmaCallbackPatched {
				progSpec.Instructions = removeSubprogramsBySymbolPrefix(
					progSpec.Instructions, "find_vma_callback")
			}
			stripProgramExtInfos(progSpec.Instructions)
		}
	}
	return patched
}

func removeSubprogramsBySymbolPrefix(insns asm.Instructions, prefix string) asm.Instructions {
	out := insns[:0]
	skipping := false
	iter := insns.Iterate()
	for iter.Next() {
		if sym := iter.Ins.Symbol(); sym != "" {
			skipping = strings.HasPrefix(sym, prefix)
		}
		if !skipping {
			out = append(out, *iter.Ins)
		}
	}
	return out
}

func stripProgramExtInfos(insns asm.Instructions) {
	iter := insns.Iterate()
	for iter.Next() {
		if btf.FuncMetadata(iter.Ins) == nil && iter.Ins.Source() == nil {
			continue
		}

		sym := iter.Ins.Symbol()
		ref := iter.Ins.Reference()
		iter.Ins.Metadata = asm.Metadata{}
		if sym != "" {
			*iter.Ins = iter.Ins.WithSymbol(sym)
		}
		if ref != "" {
			*iter.Ins = iter.Ins.WithReference(ref)
		}
	}
}

// loadRodataVars initializes RODATA variables for the eBPF programs.
func loadRodataVars(coll *cebpf.CollectionSpec, kmod *kallsyms.Module, cfg *Config,
	major, minor uint32, origins *originRegistry,
) error {
	if cfg.VerboseMode {
		if err := coll.Variables["with_debug_output"].Set(uint32(1)); err != nil {
			return fmt.Errorf("failed to set debug output: %v", err)
		}
	}

	// The Python/native hybrid unwinder's per program loop count defaults to 10
	// which is the largest that fits the 5.x / 6.0-6.5 verifier. Kernels 6.6+ are
	// more efficient and can support more, but 6.18's verifier is tighter than
	// 6.6-6.16; 15 fits the floor across the 6.6+ CI matrix.
	if major > 6 || (major == 6 && minor >= 6) {
		if err := coll.Variables["python_frames_per_program"].Set(uint32(15)); err != nil {
			return fmt.Errorf("failed to set python_frames_per_program: %v", err)
		}
	}

	if err := setOriginIDs(coll, cfg, origins); err != nil {
		return err
	}

	if err := coll.Variables["off_cpu_threshold"].Set(cfg.OffCPUThreshold); err != nil {
		return fmt.Errorf("failed to set off_cpu_threshold: %v", err)
	}

	if err := coll.Variables["filter_error_frames"].Set(cfg.FilterErrorFrames); err != nil {
		return fmt.Errorf("failed to set drop_error_only_traces: %v", err)
	}

	if err := coll.Variables["go_labels_disabled"].Set(
		cfg.InterpretersConfig.Go.IsLabelsDisabled()); err != nil {
		return fmt.Errorf("failed to set go_labels_disabled: %v", err)
	}

	if err := coll.Variables["filter_idle_frames"].Set(cfg.FilterIdleFrames); err != nil {
		return fmt.Errorf("failed to set filter_idle_frames: %v", err)
	}

	if err := coll.Variables["ruby_skip_native_resume"].Set(cfg.InterpretersConfig.Ruby.SkipNativeResume); err != nil {
		return fmt.Errorf("failed to set ruby_skip_native_resume: %v", err)
	}

	pacMask := pacmask.GetPACMask()
	if pacMask != 0 {
		log.Debugf("Determined PAC mask to be 0x%016X", pacMask)
	} else {
		log.Debug("PAC is not enabled on the system.")
	}
	if err := coll.Variables["inverse_pac_mask"].Set(^pacMask); err != nil {
		return fmt.Errorf("failed to set inverse_pac_mask: %v", err)
	}

	rodataVars := sysConfigVars{}
	configureVMALookup(coll, cfg, &rodataVars)

	// PID-namespace translation setup. Must run before prepareAnalysis so the
	// analysis probes (is_our_analysis_task) see the layout offsets via the
	// Variables copy. On any BTF / old-kernel failure we leave the offsets at 0
	// and the BPF helpers fall back to the kernel-root path.
	var translate bool
	switch cfg.PIDNamespaceTranslation {
	case "", "auto", "on":
		translate = true
	case "off":
		translate = false
	default:
		return fmt.Errorf("invalid pid_namespace_translation %q (want off|on|auto)",
			cfg.PIDNamespaceTranslation)
	}
	if translate && !parsePidStructLayout(&rodataVars) {
		translate = false
	}
	if err := setPidLayoutVars(coll, &rodataVars); err != nil {
		return err
	}

	systemAnalysisColl, maps, err := prepareAnalysis(coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if err := determineSysConfig(systemAnalysisColl, maps, kmod, cfg.InterpretersConfig, &rodataVars); err != nil {
		return fmt.Errorf("failed to determine system configs: %v", err)
	}

	// Discover the profiler's own PID-namespace depth. Only meaningful when the
	// task-walking offsets were populated; level 0 is the initial namespace,
	// where get_pid_in_profiler_ns() is a no-op.
	if translate && rodataVars.task_thread_pid_offset != 0 {
		lvl, lerr := loadPidNsLevel(systemAnalysisColl, maps)
		if lerr != nil {
			return fmt.Errorf("failed to discover profiler PID namespace level: %v", lerr)
		}
		rodataVars.profiler_pidns_level = lvl
		if lvl > 0 {
			log.Infof("PID-namespace translation active: profiler at PID namespace depth %d; "+
				"PIDs are translated into the profiler's namespace", lvl)
		}
	}
	// read_pid_level is only used at startup; drop it from the main collection so
	// it is not attached to sys_enter for the lifetime of the collector.
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
	if err := coll.Variables["vma_lookup_enabled"].Set(rodataVars.vma_lookup_enabled); err != nil {
		return fmt.Errorf("failed to set vma_lookup_enabled: %v", err)
	}
	if err := coll.Variables["vma_vm_file_offset"].Set(rodataVars.vma_vm_file_offset); err != nil {
		return fmt.Errorf("failed to set vma_vm_file_offset: %v", err)
	}
	if err := coll.Variables["vma_vm_flags_offset"].Set(rodataVars.vma_vm_flags_offset); err != nil {
		return fmt.Errorf("failed to set vma_vm_flags_offset: %v", err)
	}
	if err := coll.Variables["profiler_pidns_level"].Set(rodataVars.profiler_pidns_level); err != nil {
		return fmt.Errorf("failed to set profiler_pidns_level: %v", err)
	}

	return nil
}

// setOriginIDs assigns an origin ID to every kind of sample the tracer's
// eBPF programs can produce and writes each ID into the corresponding
// RODATA variable. Sampling is always active. Off-CPU and probe profiling
// only get one if enabled.
// TODO: this is a temporary helper and will be removed once tracer manages
// custom probes.
func setOriginIDs(coll *cebpf.CollectionSpec, cfg *Config, origins *originRegistry) error {
	sampling, err := origins.register(&samples.TypeMetadata{
		PeriodType: "cpu",
		PeriodUnit: "nanoseconds",
		SampleType: "samples",
		SampleUnit: "count",
	})
	if err != nil {
		return err
	}
	if err := coll.Variables["origin_id_sampling"].Set(sampling); err != nil {
		return fmt.Errorf("failed to set origin_id_sampling: %v", err)
	}

	if cfg.OffCPUThreshold > 0 {
		offCPU, err := origins.register(&samples.TypeMetadata{
			SampleType:   "off_cpu",
			SampleUnit:   "nanoseconds",
			ReportValues: true,
		})
		if err != nil {
			return err
		}
		if err := coll.Variables["origin_id_off_cpu"].Set(uint16(offCPU)); err != nil {
			return fmt.Errorf("failed to set origin_id_off_cpu: %v", err)
		}
	}

	if len(cfg.ProbeLinks) > 0 || cfg.LoadProbe {
		probe, err := origins.register(&samples.TypeMetadata{
			SampleType: "events",
			SampleUnit: "count",
		})
		if err != nil {
			return err
		}
		if err := coll.Variables["origin_id_probe"].Set(uint16(probe)); err != nil {
			return fmt.Errorf("failed to set origin_id_probe: %v", err)
		}
	}

	return nil
}
