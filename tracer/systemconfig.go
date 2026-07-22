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
}

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

// executeSystemAnalysisFn is a function that runs a named BPF analysis program
// against a kernel symbol address and returns the read bytes, the resolved
// address, and any error. The program name must be one of the programs
// registered in prepareAnalysis.
type executeSystemAnalysisFn = func(string, libpf.SymbolValue) ([]byte, uint64, error)

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

// executeSystemAnalysisBpfCode will execute given analysis program with the address argument.
func executeSystemAnalysisBpfCode(pid uint32, progSpec *cebpf.ProgramSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	systemAnalysis := maps["system_analysis"]

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Pid:     pid,
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
func loadKernelCode(execFn executeSystemAnalysisFn,
	address libpf.SymbolValue,
) ([]byte, error) {
	code, _, err := execFn("read_kernel_memory", address)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct will request the ebpf code to read bytes from the given offset from
// the current task_struct.
func readTaskStruct(execFn executeSystemAnalysisFn,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	return execFn("read_task_struct", address)
}

// determineStackPtregs determines the offset of `struct pt_regs` within the entry stack
// when the `stack` field offset within `task_struct` is already known.
func determineStackPtregs(execFn executeSystemAnalysisFn,
	vars *sysConfigVars,
) error {
	data, ptregs, err := readTaskStruct(execFn, libpf.SymbolValue(vars.task_stack_offset))
	if err != nil {
		return err
	}
	stackBase := binary.LittleEndian.Uint64(data)
	vars.stack_ptregs_offset = uint32(ptregs - stackBase)
	return nil
}

// determineStackLayout scans `task_struct` for offset of the `stack` field, and using
// its value determines the offset of `struct pt_regs` within the entry stack.
func determineStackLayout(execFn executeSystemAnalysisFn,
	vars *sysConfigVars,
) error {
	const maxTaskStructSize = 8 * 1024
	const maxStackSize = 64 * 1024

	pageSizeMinusOne := uint64(os.Getpagesize() - 1)

	for offs := 0; offs < maxTaskStructSize; {
		data, ptregs, err := readTaskStruct(execFn, libpf.SymbolValue(offs))
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

// loadSelfHostNamespacePID returns the host PID namespace TGID of the current
// process by running a BPF_PROG_TEST_RUN on a raw_tracepoint program that calls
// bpf_get_current_pid_tgid(). This is necessary when the profiler runs inside a
// container with its own PID namespace, where os.Getpid() returns the namespace
// PID.
//
// The ctx_in semantics differ by kernel version:
//   - Kernels 6.18+: ctx_in must be NULL (non-NULL is rejected with EINVAL).
//   - Older kernels: ctx_in must be non-NULL with ctx_size_in >= sizeof(bpf_raw_tp_regs).
//
// We try without ctx first, then fall back with a zeroed ctx buffer on EINVAL.
func loadSelfHostNamespacePID(orig *cebpf.CollectionSpec) (uint32, error) {
	testProg, err := cebpf.NewProgram(orig.Programs["store_tracer_pid"])
	if err != nil {
		return 0, err
	}
	defer testProg.Close()

	// First attempt: no ctx (kernel 6.18+ rejects non-NULL ctx_in).
	retval, err := testProg.Run(&cebpf.RunOptions{})
	if err == nil {
		return retval, nil
	}
	if !errors.Is(err, unix.EINVAL) {
		return 0, err
	}

	// Fallback for older kernels that require ctx_in != NULL with
	// ctx_size_in >= sizeof(bpf_raw_tp_regs) = 3×sizeof(struct pt_regs).
	ctx := make([]byte, 3*int(unsafe.Sizeof(unix.PtraceRegs{})))
	retval, err = testProg.Run(&cebpf.RunOptions{Context: ctx})
	if err != nil {
		return 0, err
	}
	return retval, nil
}

// prepareAnalysis creates a new CollectionSpec for the system analysis.
func prepareAnalysis(cfg *Config, orig *cebpf.CollectionSpec) (executeSystemAnalysisFn, error) {
	var tracerPid uint32
	var err error

	if cfg.RootFs != "/" && len(cfg.RootFs) != 0 {
		// When the host root filesystem is mounted at a path other than "/", the
		// profiler is running inside a container with its own PID namespace. In
		// that case os.Getpid() returns the container-namespace PID, which the
		// BPF helper (bpf_get_current_pid_tgid) would not match because it always
		// reports the host-namespace TGID. We use a BPF uprobe to capture the
		// host-namespace PID instead.
		tracerPid, err = loadSelfHostNamespacePID(orig)
		if err != nil {
			return nil, fmt.Errorf("failed to load host PID: %v", err)

		}
	} else {
		// RootFs == "/" implies the profiler shares the host PID namespace
		// (hostPID: true in Kubernetes terms), so os.Getpid() already returns
		// the host-namespace PID that the BPF helper will see.
		tracerPid = uint32(os.Getpid())
	}

	new := &cebpf.CollectionSpec{
		Maps:     make(map[string]*cebpf.MapSpec),
		Programs: make(map[string]*cebpf.ProgramSpec),
	}
	new.Maps["system_analysis"] = orig.Maps["system_analysis"].Copy()
	new.Maps[".rodata.var"] = orig.Maps[".rodata.var"].Copy()
	if rodata, ok := orig.Maps[".rodata"]; ok {
		new.Maps[".rodata"] = rodata.Copy()
	}

	new.Programs["read_kernel_memory"] = orig.Programs["read_kernel_memory"].Copy()
	new.Programs["read_task_struct"] = orig.Programs["read_task_struct"].Copy()

	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{InterpretersConfig: interpreterconfig.AllInterpreters()}, maps); err != nil {
		return nil, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	return func(programName string, sv libpf.SymbolValue) ([]byte, uint64, error) {
		return executeSystemAnalysisBpfCode(tracerPid, new.Programs[programName], maps, sv)
	}, nil
}

func determineSysConfig(setupFn executeSystemAnalysisFn,
	kmod *kallsyms.Module, interpretersConfig interpreterconfig.Config, vars *sysConfigVars,
) error {
	if err := parseBTF(vars); err != nil {
		log.Infof("Using binary analysis (BTF not available: %s)", err)

		if err = determineStackLayout(setupFn, vars); err != nil {
			return err
		}

		if !interpretersConfig.Perl.IsDisabled() || !interpretersConfig.Python.IsDisabled() ||
			!interpretersConfig.Go.IsLabelsDisabled() {
			var tpbaseOffset uint64
			tpbaseOffset, err = loadTPBaseOffset(setupFn, kmod)
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
		if err := determineStackPtregs(setupFn, vars); err != nil {
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
	major, minor, patch uint32, origins *originRegistry,
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

	systemAnalysisFn, err := prepareAnalysis(cfg, coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if cfg.KernelVersionCheck {
		if hasProbeReadBug(major, minor, patch) {
			if err = checkForMaccessPatch(systemAnalysisFn, kmod); err != nil {
				return fmt.Errorf("your kernel version %d.%d.%d may be "+
					"affected by a Linux kernel bug that can lead to system "+
					"freezes, terminating host agent now to avoid "+
					"triggering this bug.\n"+
					"If you are certain your kernel is not affected, "+
					"you can override this check at your own risk "+
					"with -no-kernel-version-check.\n"+
					"Error: %v", major, minor, patch, err)
			}
		}
	}

	if err := determineSysConfig(systemAnalysisFn, kmod, cfg.InterpretersConfig, &rodataVars); err != nil {
		return fmt.Errorf("failed to determine system configs: %v", err)
	}
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
