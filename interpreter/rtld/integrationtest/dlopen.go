//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrationtest contains the QEMU-driven integration test for the
// rtld interpreter's dlopen uprobe. It is a sibling of package rtld (rather
// than an internal test) to avoid an import cycle: the test needs to
// construct a Tracer (importing tracer -> execinfomanager -> rtld), and
// internal tests inside package rtld would close that cycle.
package integrationtest // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld/integrationtest"

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include <stdlib.h>
import "C"
import (
	"errors"
	"unsafe"
)

// dlopenLib is a thin cgo wrapper around dlopen()/dlclose() used to fire the
// uprobe in libc. It lives in a non-_test.go file because cgo is not
// permitted inside _test.go.
func dlopenLib(name string) error {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	h := C.dlopen(cs, C.RTLD_LAZY)
	if h == nil {
		return errors.New("dlopen returned NULL")
	}
	C.dlclose(h)
	return nil
}
