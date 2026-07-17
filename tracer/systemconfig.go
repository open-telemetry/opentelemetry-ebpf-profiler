// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/pacmask"
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
func executeSystemAnalysisBpfCode(progSpec *cebpf.ProgramSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	systemAnalysis := maps["system_analysis"]

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Done:    false,
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
	if !data.Done {
		return fmt.Errorf("%w at 0x%x", errSystemAnalysisNotHandled, address)
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

func retrievePkgName(val any) string {
	pc := reflect.ValueOf(val).Pointer()
	return runtime.FuncForPC(pc).Name()
}

func loadTracerPID(orig *cebpf.CollectionSpec) (uint32, error) {
	selfFilePath, err := os.Executable()
	if err != nil {
		return 0, err
	}
	file, err := pfelf.Open(selfFilePath)
	if err != nil {
		return 0, err
	}
	goPclntab, err := elfunwindinfo.NewGopclntab(file)
	if err != nil {
		return 0, err
	}
	symbolName := retrievePkgName(storePid)
	sym, err := goPclntab.LookupSymbol(libpf.SymbolName(symbolName))
	if err != nil {
		return 0, err
	}
	addr, err := file.VirtAddrToFileOffset(uint64(sym.Address))
	if err != nil {
		return 0, err
	}
	progSpec, err := ParseProbe(fmt.Sprintf("uprobe:%s:%s", selfFilePath, symbolName))
	if err != nil {
		return 0, err
	}

	new := &cebpf.CollectionSpec{
		Maps:     make(map[string]*cebpf.MapSpec),
		Programs: make(map[string]*cebpf.ProgramSpec),
	}
	new.Maps["tracer_pid_m"] = orig.Maps["tracer_pid_m"].Copy()
	new.Programs["store_tracer_pid"] = orig.Programs["store_tracer_pid"].Copy()
	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{}, maps); err != nil {
		return 0, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return 0, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	uprobeProg, err := cebpf.NewProgram(new.Programs["store_tracer_pid"])
	if err != nil {
		return 0, err
	}
	ex, err := link.OpenExecutable(progSpec.Target)
	if err != nil {
		return 0, err
	}

	uprobeLink, err := ex.Uprobe(progSpec.Symbol, uprobeProg, &link.UprobeOptions{Address: addr})
	if err != nil {
		return 0, err
	}
	defer uprobeLink.Close()
	// trigger uprobe
	storePid()

	key0 := uint32(0)
	var tracerPid uint32
	if err = maps["tracer_pid_m"].Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&tracerPid)); err != nil {
		return 0, err
	}

	return tracerPid, nil
}

//go:noinline
func storePid() {}

// prepareAnalysis creates a new CollectionSpec for the system analysis.
func prepareAnalysis(orig *cebpf.CollectionSpec) (*cebpf.CollectionSpec, map[string]*cebpf.Map, error) {
	tracerPid, err := loadTracerPID(orig)
	if err != nil {
		return nil, nil, err
	}

	if err := orig.Variables["tracer_pid"].Set(tracerPid); err != nil {
		return nil, nil, fmt.Errorf("failed to set tracer_pid: %v", err)
	}

	// VariableSpec.Set only updates the in-memory Value; it does not write
	// into the MapSpec byte slice. Sync now so the .Copy() below picks up
	// the correct tracer_pid bytes.
	if err := syncVariablesToMapSpecs(orig); err != nil {
		return nil, nil, fmt.Errorf("failed to sync tracer_pid to rodata: %v", err)
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
		if err := determineStackPtregs(coll, maps, vars); err != nil {
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
	major, minor uint32,
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

	systemAnalysisColl, maps, err := prepareAnalysis(coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if err := determineSysConfig(systemAnalysisColl, maps, kmod, cfg.InterpretersConfig, &rodataVars); err != nil {
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
