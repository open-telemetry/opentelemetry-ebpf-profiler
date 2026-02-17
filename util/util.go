// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package util // import "go.opentelemetry.io/ebpf-profiler/util"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"golang.org/x/sys/unix"
)

// IsValidString checks if string is UTF-8-encoded and only contains expected characters.
func IsValidString(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// AtomicUpdateMaxUint32 updates the value in store using atomic memory primitives. newValue will
// only be placed in store if newValue is larger than the current value in store.
// To avoid inconsistency parallel updates to store should be avoided.
func AtomicUpdateMaxUint32(store *atomic.Uint32, newValue uint32) {
	for {
		// Load the current value
		oldValue := store.Load()
		if newValue <= oldValue {
			// No update needed.
			break
		}
		if store.CompareAndSwap(oldValue, newValue) {
			// The value was atomically updated.
			break
		}
		// The value changed between load and update attempt.
		// Retry with the new value.
	}
}

// Range describes a range with Start and End values.
type Range struct {
	Start uint64
	End   uint64
}

// OnDiskFileIdentifier can be used as unique identifier for a file.
// It is a structure to identify a particular file on disk by
// deviceID and inode number.
type OnDiskFileIdentifier struct {
	DeviceID uint64 // dev_t as reported by stat.
	InodeNum uint64 // ino_t should fit into 64 bits
}

func (odfi OnDiskFileIdentifier) Hash32() uint32 {
	return uint32(hash.Uint64(odfi.InodeNum) + odfi.DeviceID)
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

var (
	// testOnlyMultiUprobeOverride allows tests to override HasMultiUprobeSupport
	testOnlyMultiUprobeOverride *bool
	// multiUprobeSupportCache caches the result of probing for multi-uprobe support
	multiUprobeSupportOnce   sync.Once
	multiUprobeSupportCached bool
	// bpfGetAttachCookieCache caches the result of probing for bpf_get_attach_cookie support
	bpfGetAttachCookieOnce   sync.Once
	bpfGetAttachCookieCached bool
)

// SetTestOnlyMultiUprobeSupport overrides HasMultiUprobeSupport for testing.
// Pass nil to restore normal behavior.
func SetTestOnlyMultiUprobeSupport(override *bool) {
	testOnlyMultiUprobeOverride = override
}

// probeBpfGetAttachCookie tests if the kernel supports bpf_get_attach_cookie by attempting
// to load a minimal BPF program that uses it. This is more reliable than checking kernel
// versions since support can be backported.
func probeBpfGetAttachCookie() bool {
	// Create a minimal program that calls bpf_get_attach_cookie
	// This is equivalent to libbpf's probe_kern_bpf_cookie function
	insns := asm.Instructions{
		// Call bpf_get_attach_cookie() - BPF_FUNC_get_attach_cookie = 80
		asm.FnGetAttachCookie.Call(),
		// Exit
		asm.Return(),
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.TracePoint,
		Instructions: insns,
		License:      "GPL",
	}

	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err != nil {
		return false
	}
	if err := prog.Close(); err != nil {
		log.Warnf("Failed to close test program: %v", err)
	}
	return true
}

// HasBpfGetAttachCookie checks if the kernel supports the bpf_get_attach_cookie helper.
// This function uses a cached, once-calculated value for performance.
//
// Note: This function requires CAP_BPF or CAP_SYS_ADMIN capabilities to load the probe
// program. The profiler should already have these privileges.
func HasBpfGetAttachCookie() bool {
	bpfGetAttachCookieOnce.Do(func() {
		bpfGetAttachCookieCached = probeBpfGetAttachCookie()
	})

	return bpfGetAttachCookieCached
}

// probeBpfUprobeMultiLink probes for uprobe_multi link support by attempting to create
// an invalid uprobe_multi link. This is modeled after libbpf's probe_uprobe_multi_link
// and cilium/ebpf's haveBPFLinkUprobeMulti which is not exposed publicly.
//
// Try to create a link to (invalid binary) which should fail with EBADF if supported
func probeBpfUprobeMultiLink() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_upm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceUprobeMulti,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return false
	}
	if err != nil {
		log.Warnf("Failed to create test program for uprobe_multi link probe: %v", err)
		return false
	}
	defer prog.Close()

	ex := link.Executable{}

	_, err = ex.UprobeMulti([]string{""}, prog, &link.UprobeMultiOptions{
		Addresses: []uint64{1},
	})

	if errors.Is(err, unix.EBADF) {
		return true
	}

	if errors.Is(err, unix.EINVAL) {
		return false
	}

	log.Warnf("Unexpected error when probing for uprobe_multi link support: %v", err)
	return false
}

// probeProgArrayAttachTypeCompat checks whether the kernel allows programs with
// different expected_attach_type values in the same BPF_MAP_TYPE_PROG_ARRAY.
// Kernels 6.12+ (commit 4540aed51b12) enforce that all programs in a prog array
// share the same expected_attach_type, which prevents mixing default kprobe
// programs with AttachTraceUprobeMulti programs in the same tail call map.
//
// Returns true if mixed attach types are allowed (pre-6.12 behavior).
func probeProgArrayAttachTypeCompat() bool {
	progArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		log.Warnf("Failed to create test prog array: %v", err)
		return true // assume compatible if we can't test
	}
	defer progArray.Close()

	minimalInsns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Load a program with default attach type (like our kprobe unwinders).
	defaultProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "probe_default",
		Type:         ebpf.Kprobe,
		Instructions: minimalInsns,
		License:      "MIT",
	})
	if err != nil {
		log.Warnf("Failed to create default attach type program: %v", err)
		return true
	}
	defer defaultProg.Close()

	// Load a program with AttachTraceUprobeMulti (like our USDT programs).
	multiProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "probe_multi",
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachTraceUprobeMulti,
		Instructions: minimalInsns,
		License:      "MIT",
	})
	if err != nil {
		log.Warnf("Failed to create uprobe_multi program: %v", err)
		return true
	}
	defer multiProg.Close()

	// Insert the default program first.
	key0 := uint32(0)
	fd0 := uint32(defaultProg.FD())
	if err := progArray.Update(unsafe.Pointer(&key0), unsafe.Pointer(&fd0),
		ebpf.UpdateAny); err != nil {
		log.Warnf("Failed to insert default program into prog array: %v", err)
		return true
	}

	// Try to insert the multi-uprobe program into the same array.
	// On 6.12+ this will fail with EINVAL due to attach type mismatch.
	key1 := uint32(1)
	fd1 := uint32(multiProg.FD())
	err = progArray.Update(unsafe.Pointer(&key1), unsafe.Pointer(&fd1), ebpf.UpdateAny)

	return err == nil
}

// HasMultiUprobeSupport checks if the kernel supports uprobe multi-attach.
// Multi-uprobes allow attaching one BPF program to multiple probe points with a single syscall,
// which is more efficient than individual uprobe attachments.
// This function probes for uprobe_multi link support, which was introduced in kernel 6.6.
//
// On kernels 6.12+ which enforce that all programs in a BPF_MAP_TYPE_PROG_ARRAY share the same
// expected_attach_type, multi-uprobe is disabled because the unwinder tail call programs in
// kprobe_progs use the default attach type which is incompatible with AttachTraceUprobeMulti.
//
// Note: This function requires CAP_BPF or CAP_SYS_ADMIN capabilities to load the probe
// program. The profiler should already have these privileges.
//
// The behavior can be overridden by:
// - Setting PARCA_DISABLE_MULTIPROBE=1 environment variable to force single-shot uprobe mode
// - Using SetTestOnlyMultiUprobeSupport() for testing purposes
func HasMultiUprobeSupport() bool {
	// Check for test override first (takes precedence over everything)
	if testOnlyMultiUprobeOverride != nil {
		return *testOnlyMultiUprobeOverride
	}

	// Cache the probe result since it's expensive to check
	multiUprobeSupportOnce.Do(func() {
		// Check for environment variable override inside the Do() to ensure
		// it's only evaluated once and consistently cached
		if os.Getenv("PARCA_DISABLE_MULTIPROBE") == "1" {
			multiUprobeSupportCached = false
		} else {
			multiUprobeSupportCached = probeBpfUprobeMultiLink() &&
				probeProgArrayAttachTypeCompat()
		}
	})

	return multiUprobeSupportCached
}

// ProgArrayReferences returns a list of instructions which load a specified tail
// call FD.
func ProgArrayReferences(perfTailCallMapFD int, insns asm.Instructions) []int {
	insNos := []int{}
	for i := range insns {
		ins := &insns[i]
		if asm.OpCode(ins.OpCode.Class()) != asm.OpCode(asm.LdClass) {
			continue
		}
		m := ins.Map()
		if m == nil {
			continue
		}
		if perfTailCallMapFD == m.FD() {
			insNos = append(insNos, i)
		}
	}
	return insNos
}
