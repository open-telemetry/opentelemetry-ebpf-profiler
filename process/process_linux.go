//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openInRoot securely opens a file within a given root directory using openat2
// with RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS to prevent symlink escapes from
// containers. It opens with O_PATH first (never blocks on FIFOs or sockets),
// verifies the target is a non-empty regular file, then reopens for reading.
func openInRoot(rootPath, filePath string) (*os.File, error) {
	rootDir, err := unix.Open(rootPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", rootPath, err)
	}
	defer unix.Close(rootDir)

	fd, err := unix.Openat2(rootDir, filePath, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("openat2 %s in %s: %w", filePath, rootPath, err)
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("fstat %s: %w", filePath, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s: not a regular file", filePath)
	}
	if stat.Size == 0 {
		return nil, fmt.Errorf("%s: empty file", filePath)
	}

	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, fmt.Errorf("reopen %s: %w", filePath, err)
	}
	return f, nil
}

// checkInodeDeviceMapping verifies that the open file f corresponds to the
// mapping m by comparing inode and device numbers.
func checkInodeDeviceMapping(f *os.File, m *RawMapping) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return fmt.Errorf("fstat %s: %w", m.Path, err)
	}
	if stat.Ino != m.Inode || stat.Dev != m.Device {
		return fmt.Errorf("inode/device mismatch for %s: got %d/%d, expected %d/%d",
			m.Path, stat.Dev, stat.Ino, m.Device, m.Inode)
	}
	return nil
}
