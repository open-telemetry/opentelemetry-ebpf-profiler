//go:build linux
// +build linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/elastic/otel-profiling-agent/rlimit"
	"github.com/elastic/otel-profiling-agent/util"

	"golang.org/x/sys/unix"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	log "github.com/sirupsen/logrus"
)

// ProbeBPFSyscall checks if the syscall EBPF is available on the system.
func ProbeBPFSyscall() error {
	_, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_TYPE_UNSPEC), uintptr(0), 0)
	if errNo == unix.ENOSYS {
		return errors.New("eBPF syscall is not available on your system")
	}
	return nil
}

// getTracepointID returns the system specific tracepoint ID for a given tracepoint.
func getTracepointID(tracepoint string) (uint64, error) {
	id, err := os.ReadFile("/sys/kernel/debug/tracing/events/syscalls/" + tracepoint + "/id")
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for %s: %v", tracepoint, err)
	}
	tid := util.DecToUint64(strings.TrimSpace(string(id)))
	return tid, nil
}

// GetCurrentKernelVersion returns the major, minor and patch version of the kernel of the host
// from the utsname struct.
func GetCurrentKernelVersion() (major, minor, patch uint32, err error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0, 0, fmt.Errorf("could not get Kernel Version: %v", err)
	}
	_, _ = fmt.Fscanf(bytes.NewReader(uname.Release[:]), "%d.%d.%d", &major, &minor, &patch)
	return major, minor, patch, nil
}

// ProbeTracepoint checks if tracepoints are available on the system, so we can attach
// our eBPF code there.
func ProbeTracepoint() error {
	ins := asm.Instructions{
		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// The check of the kernel version was removed with
	// commit 6c4fc209fcf9d27efbaa48368773e4d2bfbd59aa. So kernel < 4.20
	// need to set the kernel version to not be rejected by the verifier.
	major, minor, patch, err := GetCurrentKernelVersion()
	if err != nil {
		return err
	}
	kernelVersion := util.VersionUint(major, minor, patch)
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to increase rlimit: %v", err)
	}
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(&cebpf.ProgramSpec{
		Type:          cebpf.TracePoint,
		License:       "GPL",
		Instructions:  ins,
		KernelVersion: kernelVersion,
	})
	if err != nil {
		return fmt.Errorf("failed to create tracepoint_probe: %v", err)
	}
	defer prog.Close()

	var tid uint64
	// sys_enter_mmap is the first tracepoint we have used
	tid, err = getTracepointID("sys_enter_mmap")
	if err != nil {
		return fmt.Errorf("failed to get id for tracepoint: %v", err)
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      tid,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("unable to open perf events: %v", err)
	}
	defer func() {
		if err = unix.Close(pfd); err != nil {
			log.Fatalf("Failed to close tracepoint sys_enter_mmap probe: %v", err)
		}
	}()

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd),
		unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
		return fmt.Errorf("unable to set up perf events: %d", errno)
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd),
		unix.PERF_EVENT_IOC_SET_BPF, uintptr(prog.FD())); errno != 0 {
		return fmt.Errorf("unable to attach bpf program to perf event %d: %d", tid, errno)
	}

	// The test was successful, so disable the tracepoint and clean up.
	// In kernel < 4.15 we can not attach multiple eBPF programs to the same tracepoint.
	// This was changed in the kernel with commit e87c6bc3852b981e71c757be20771546ce9f76f3.
	// So it is important not only to disable the tracepoint but also close its
	// perf event file descriptor.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd),
		unix.PERF_EVENT_IOC_DISABLE, 0); errno != 0 {
		return fmt.Errorf("unable to disable perf events: %v", err)
	}
	return nil
}
