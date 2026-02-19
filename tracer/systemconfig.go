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
	// structure offsets for namespace PID translation.
	task_nsproxy_off                uint32
	task_thread_pid_off             uint32
	task_group_leader_off           uint32
	nsproxy_pid_ns_for_children_off uint32
	pid_ns_inum_off                 uint32
	pid_level_off                   uint32
	pid_numbers_off                 uint32
	upid_nr_off                     uint32
	upid_size                       uint32
	// whether namespace PID translation is enabled.
	// Tt requires to have BTF support for the kernel and
	// to be enabled in the configuration.
	ns_translation_enabled bool
}

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

// parseBTFForNsTranslation resolves the SystemConfig data from kernel BTF
// for namespace PID translation.
// It requires to have BTF support for the kernel and
// to be enabled in the configuration.
func parseBTFForNsTranslation(vars *sysConfigVars, spec *btf.Spec) error {
	var taskStruct *btf.Struct
	err := spec.TypeByName("task_struct", &taskStruct)
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

	// Offsets for get_virtual_ids (namespace inode, vpid, vtgid)
	nsproxyOff, err := calculateFieldOffset(taskStruct, "nsproxy")
	if err != nil {
		return err
	}
	vars.task_nsproxy_off = uint32(nsproxyOff)

	threadPidOff, err := calculateFieldOffset(taskStruct, "thread_pid")
	if err != nil {
		return err
	}
	vars.task_thread_pid_off = uint32(threadPidOff)

	groupLeaderOff, err := calculateFieldOffset(taskStruct, "group_leader")
	if err != nil {
		return err
	}
	vars.task_group_leader_off = uint32(groupLeaderOff)

	var nsproxyStruct *btf.Struct
	if err = spec.TypeByName("nsproxy", &nsproxyStruct); err != nil {
		return err
	}
	pidNsForChildrenOff, err := calculateFieldOffset(nsproxyStruct, "pid_ns_for_children")
	if err != nil {
		return err
	}
	vars.nsproxy_pid_ns_for_children_off = uint32(pidNsForChildrenOff)

	var pidNamespaceStruct *btf.Struct
	if err = spec.TypeByName("pid_namespace", &pidNamespaceStruct); err != nil {
		return err
	}
	// inum is in ns_common embedded as "ns" in pid_namespace
	pidNsInumOff, err := calculateFieldOffset(pidNamespaceStruct, "ns.inum")
	if err != nil {
		return err
	}
	vars.pid_ns_inum_off = uint32(pidNsInumOff)

	var pidStruct *btf.Struct
	if err = spec.TypeByName("pid", &pidStruct); err != nil {
		return err
	}
	levelOff, err := calculateFieldOffset(pidStruct, "level")
	if err != nil {
		return err
	}
	vars.pid_level_off = uint32(levelOff)

	numbersMember, err := memberByName(pidStruct, "numbers")
	if err != nil {
		return err
	}
	vars.pid_numbers_off = uint32(numbersMember.Offset.Bytes())
	arr, ok := numbersMember.Type.(*btf.Array)
	if !ok {
		return fmt.Errorf("pid.numbers is not an array")
	}
	upidSize, err := btf.Sizeof(arr.Type)
	if err != nil {
		return err
	}
	vars.upid_size = uint32(upidSize)

	var upidStruct *btf.Struct
	if err = spec.TypeByName("upid", &upidStruct); err != nil {
		return err
	}
	nrOff, err := calculateFieldOffset(upidStruct, "nr")
	if err != nil {
		return err
	}
	vars.upid_nr_off = uint32(nrOff)
	// namespace PID translation is enabled
	vars.ns_translation_enabled = true
	return nil
}

// parseBTF resolves the SystemConfig data from kernel BTF
func parseBTF(vars *sysConfigVars, spec *btf.Spec) error {
	var taskStruct *btf.Struct
	err := spec.TypeByName("task_struct", &taskStruct)
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

	return nil
}

// loadBTFSpec loads the BTF spec from the kernel.
func loadBTFSpec() (*btf.Spec, error) {
	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return btf.LoadSplitSpecFromReader(fh, nil)
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

	return data.Code[:], data.Address, nil
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
		Maps:     make(map[string]*cebpf.MapSpec),
		Programs: make(map[string]*cebpf.ProgramSpec),
	}
	new.Maps["system_analysis"] = orig.Maps["system_analysis"].Copy()
	new.Maps[".rodata.var"] = orig.Maps[".rodata.var"].Copy()

	new.Programs["read_kernel_memory"] = orig.Programs["read_kernel_memory"].Copy()
	new.Programs["read_task_struct"] = orig.Programs["read_task_struct"].Copy()

	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{}, maps); err != nil {
		return nil, nil, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	return new, maps, nil
}

// getCurrentNS reads the inode and device number from the given filename
// which is typically /proc/self/ns/pid.
func getCurrentNS(filename string) (uint64, uint64, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return 0, 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("not a syscall.Stat_t")
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func determineSysConfig(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kmod *kallsyms.Module, includeTracers types.IncludedTracers, enableNamespacePID bool, vars *sysConfigVars,
) error {
	btfResolution := true
	spec, err := loadBTFSpec()
	if err != nil {
		btfResolution = false
	}
	if btfResolution {
		if err := parseBTF(vars, spec); err != nil {
			btfResolution = false
		}
	}

	if enableNamespacePID {
		if !btfResolution {
			return fmt.Errorf("configuration error: namespace PID translation is enabled but BTF resolution is not available")
		}
		if err := parseBTFForNsTranslation(vars, spec); err != nil {
			return err
		}
	}

	if !btfResolution {
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

	log.Infof("Found offsets: task stack %#x, pt_regs %#x, tpbase %#x, ns_translation_enabled %t",
		vars.task_stack_offset,
		vars.stack_ptregs_offset,
		vars.tpbase_offset,
		vars.ns_translation_enabled)

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

	systemAnalysisColl, maps, err := prepareAnalysis(coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if err := determineSysConfig(systemAnalysisColl,
		maps,
		kmod,
		cfg.IncludeTracers,
		cfg.EnableNamespacePID,
		&rodataVars); err != nil {
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

	// ns_translation_enabled is set to true if namespace PID translation is enabled
	// and BTF resolution is successful.
	if rodataVars.ns_translation_enabled {
		// set pid_ns_translation_enabled to true, which is used in `native_tracer_entry`
		// to determine if namespace PID translation has to be done.
		if err := coll.Variables["pid_ns_translation_enabled"].Set(uint8(1)); err != nil {
			return fmt.Errorf("failed to set pid_ns_translation_enabled: %v", err)
		}
		dev, ns, err := getCurrentNS("/proc/self/ns/pid")
		if err != nil {
			return fmt.Errorf("failed to read my namespace: %v", err)
		}
		if err := coll.Variables["target_pid_ns_inode"].Set(ns); err != nil {
			return fmt.Errorf("failed to set target_pid_ns_inode: %v", err)
		}
		if err := coll.Variables["target_pid_ns_dev"].Set(dev); err != nil {
			return fmt.Errorf("failed to set target_pid_ns_dev: %v", err)
		}

		if err := coll.Variables["task_nsproxy_off"].Set(rodataVars.task_nsproxy_off); err != nil {
			return fmt.Errorf("failed to set task_nsproxy_off: %v", err)
		}
		if err := coll.Variables["task_thread_pid_off"].Set(rodataVars.task_thread_pid_off); err != nil {
			return fmt.Errorf("failed to set task_thread_pid_off: %v", err)
		}
		if err := coll.Variables["task_group_leader_off"].Set(rodataVars.task_group_leader_off); err != nil {
			return fmt.Errorf("failed to set task_group_leader_off: %v", err)
		}
		if err := coll.Variables["nsproxy_pid_ns_for_children_off"].Set(rodataVars.nsproxy_pid_ns_for_children_off); err != nil {
			return fmt.Errorf("failed to set nsproxy_pid_ns_for_children_off: %v", err)
		}
		if err := coll.Variables["pid_ns_inum_off"].Set(rodataVars.pid_ns_inum_off); err != nil {
			return fmt.Errorf("failed to set pid_ns_inum_off: %v", err)
		}
		if err := coll.Variables["pid_level_off"].Set(rodataVars.pid_level_off); err != nil {
			return fmt.Errorf("failed to set pid_level_off: %v", err)
		}
		if err := coll.Variables["pid_numbers_off"].Set(rodataVars.pid_numbers_off); err != nil {
			return fmt.Errorf("failed to set pid_numbers_off: %v", err)
		}
		if err := coll.Variables["upid_nr_off"].Set(rodataVars.upid_nr_off); err != nil {
			return fmt.Errorf("failed to set upid_nr_off: %v", err)
		}
		if err := coll.Variables["upid_size"].Set(rodataVars.upid_size); err != nil {
			return fmt.Errorf("failed to set upid_size: %v", err)
		}
	}

	return nil
}
