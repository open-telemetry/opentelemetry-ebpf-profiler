//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openInRoot opens filePath relative to rootPath. On non-Linux platforms
// RESOLVE_IN_ROOT is unavailable, so this uses openat(2) with O_NOFOLLOW
// to at least prevent following symlinks on the final path component.
func openInRoot(rootPath, filePath string) (*os.File, error) {
	rootDir, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", rootPath, err)
	}
	defer unix.Close(rootDir)

	fd, err := unix.Openat(rootDir, filePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("openat %s in %s: %w", filePath, rootPath, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fstat %s: %w", filePath, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, fmt.Errorf("%s: not a regular file", filePath)
	}
	if stat.Size == 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("%s: empty file", filePath)
	}

	return os.NewFile(uintptr(fd), filePath), nil
}

func checkInodeDeviceMapping(f *os.File, m *RawMapping) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return fmt.Errorf("fstat %s: %w", m.Path, err)
	}
	if stat.Ino != m.Inode || uint64(stat.Dev) != m.Device {
		return fmt.Errorf("inode/device mismatch for %s: got %d/%d, expected %d/%d",
			m.Path, stat.Dev, stat.Ino, m.Device, m.Inode)
	}
	return nil
}
