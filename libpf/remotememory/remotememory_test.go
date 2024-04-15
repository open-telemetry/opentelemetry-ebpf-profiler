/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package remotememory

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/libpf"
)

func assertEqual(t *testing.T, a, b any) {
	if a == b {
		return
	}
	t.Errorf("Received %v (type %v), expected %v (type %v)",
		a, reflect.TypeOf(a), b, reflect.TypeOf(b))
}

func RemoteMemTests(t *testing.T, rm RemoteMemory) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dataPtr := libpf.Address(uintptr(unsafe.Pointer(&data[0])))
	str := []byte("this is a string\x00")
	strPtr := libpf.Address(uintptr(unsafe.Pointer(&str[0])))
	longStr := append(bytes.Repeat([]byte("long test string"), 4095/16), 0x00)
	longStrPtr := libpf.Address(uintptr(unsafe.Pointer(&longStr[0])))

	foo := make([]byte, len(data))
	err := rm.Read(libpf.Address(uintptr(unsafe.Pointer(&data))), foo)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) {
			t.Skipf("skipping due to error: %v", err)
		}
		t.Fatalf("%v", err)
	}

	assertEqual(t, rm.Uint32(dataPtr), uint32(0x04030201))
	assertEqual(t, rm.Ptr(dataPtr), libpf.Address(0x0807060504030201))
	assertEqual(t, rm.String(strPtr), string(str[:len(str)-1]))
	assertEqual(t, rm.String(longStrPtr), string(longStr[:len(longStr)-1]))

	rr := rm.Reader(dataPtr, 2)
	for i := 0; i < len(data)-1; i++ {
		if b, err := rr.ReadByte(); err == nil {
			assertEqual(t, b, data[i])
		} else {
			t.Errorf("recordingreader error: %v", err)
			break
		}
	}
	assertEqual(t, len(rr.GetBuffer()), len(data)-1)
}

func TestProcessVirtualMemory(t *testing.T) {
	RemoteMemTests(t, NewProcessVirtualMemory(libpf.PID(os.Getpid())))
}
