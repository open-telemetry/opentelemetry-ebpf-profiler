//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package linux // import "go.opentelemetry.io/ebpf-profiler/internal/linux"

import (
	"bytes"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

type kernelVersion struct {
	major, minor, patch uint32
}

var getKernelVersion = sync.OnceValues(func() (kernelVersion, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return kernelVersion{}, err
	}
	var major, minor, patch uint32
	_, _ = fmt.Fscanf(bytes.NewReader(uname.Release[:]), "%d.%d.%d", &major, &minor, &patch)
	return kernelVersion{major: major, minor: minor, patch: patch}, nil
})

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
