/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package nopanicslicereader

import (
	"reflect"
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
)

func assertEqual(t *testing.T, a, b any) {
	if a == b {
		return
	}
	t.Errorf("Received %v (type %v), expected %v (type %v)",
		a, reflect.TypeOf(a), b, reflect.TypeOf(b))
}

func TestSliceReader(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	assertEqual(t, Uint16(data, 2), uint16(0x0403))
	assertEqual(t, Uint16(data, 7), uint16(0))
	assertEqual(t, Uint32(data, 0), uint32(0x04030201))
	assertEqual(t, Uint32(data, 100), uint32(0))
	assertEqual(t, Uint64(data, 0), uint64(0x0807060504030201))
	assertEqual(t, Uint64(data, 1), uint64(0))
	assertEqual(t, Ptr(data, 0), libpf.Address(0x0807060504030201))
	assertEqual(t, PtrDiff32(data, 4), libpf.Address(0x08070605))
}
