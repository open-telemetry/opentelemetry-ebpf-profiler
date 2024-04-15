/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package pfnamespaces

import (
	"fmt"
	"syscall"

	"go.uber.org/multierr"

	"golang.org/x/sys/unix"
)

// EnterNamespace enters a new namespace of the specified type, inherited from the provided PID.
// The returned file descriptor must be closed with unix.Close().
// Note that this function affects the OS thread calling this function, which will likely impact
// more than one goroutine unless you also use runtime.LockOSThread.
func EnterNamespace(pid int, nsType string) (int, error) {
	var nsTypeInt int
	switch nsType {
	case "net":
		nsTypeInt = syscall.CLONE_NEWNET
	case "uts":
		nsTypeInt = syscall.CLONE_NEWUTS
	default:
		return -1, fmt.Errorf("unsupported namespace type: %s", nsType)
	}

	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	err = unix.Setns(fd, nsTypeInt)
	if err != nil {
		// Close namespace and return the error
		return -1, multierr.Combine(err, unix.Close(fd))
	}

	return fd, nil
}
