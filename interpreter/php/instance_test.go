// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// mockMemory implements io.ReaderAt for testing PHP remote memory reads.
// It stores data as a set of (address, bytes) regions.
type mockMemory struct {
	regions []memRegion
}

type memRegion struct {
	addr uint64
	data []byte
}

func newMockMemory() *mockMemory {
	return &mockMemory{}
}

func (m *mockMemory) writeAt(addr uint64, data []byte) {
	m.regions = append(m.regions, memRegion{addr: addr, data: append([]byte{}, data...)})
}

func (m *mockMemory) writeUint64(addr uint64, val uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	m.writeAt(addr, buf)
}

func (m *mockMemory) writeString(addr uint64, s string) {
	// Write null-terminated string
	m.writeAt(addr, append([]byte(s), 0))
}

func (m *mockMemory) ReadAt(p []byte, off int64) (n int, err error) {
	addr := uint64(off)
	for _, r := range m.regions {
		// Allow reads that start within a region, even if they extend beyond it
		if addr >= r.addr && addr < r.addr+uint64(len(r.data)) {
			offset := addr - r.addr
			n = copy(p, r.data[offset:])
			if n < len(p) {
				return n, io.EOF
			}
			return n, nil
		}
	}
	return 0, io.EOF
}

// buildDefaultVMStructs returns a phpData with standard PHP 8.x offsets for testing.
func buildDefaultVMStructs() *phpData {
	d := &phpData{version: phpVersion(8, 0, 0)}
	vms := &d.vmStructs
	vms.zend_executor_globals.current_execute_data = 488
	vms.zend_execute_data.opline = 0
	vms.zend_execute_data.function = 24
	vms.zend_execute_data.this_type_info = 40
	vms.zend_execute_data.prev_execute_data = 48
	vms.zend_function.common_type = 0
	vms.zend_function.common_funcname = 8
	vms.zend_function.common_scope = 16
	vms.zend_function.op_array_filename = 144
	vms.zend_function.op_array_linestart = 152
	vms.zend_function.Sizeof = 168
	vms.zend_string.val = 24
	vms.zend_class_entry.name = 8
	vms.zend_op.lineno = 24
	return d
}

func TestGetFunction_ClassName(t *testing.T) {
	tests := []struct {
		name             string
		funcName         string
		className        string
		hasScope         bool
		expectedFuncName string
	}{
		{
			name:             "method with class name",
			funcName:         "index",
			className:        "UserController",
			hasScope:         true,
			expectedFuncName: "UserController::index",
		},
		{
			name:             "function without class (no scope pointer)",
			funcName:         "array_map",
			className:        "",
			hasScope:         false,
			expectedFuncName: "array_map",
		},
		{
			name:             "method with namespaced class",
			funcName:         "handle",
			className:        "App\\Http\\Middleware\\Auth",
			hasScope:         true,
			expectedFuncName: "App\\Http\\Middleware\\Auth::handle",
		},
		{
			name:             "scope pointer set but class name string is empty",
			funcName:         "doSomething",
			className:        "",
			hasScope:         true,
			expectedFuncName: "doSomething",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := newMockMemory()
			d := buildDefaultVMStructs()
			vms := &d.vmStructs

			// Layout addresses
			const (
				funcObjAddr       = uint64(0x1000)
				funcNameStrAddr   = uint64(0x2000)
				classEntryAddr    = uint64(0x3000)
				classNameStrAddr  = uint64(0x4000)
				sourceFileStrAddr = uint64(0x5000)
			)

			// Build the zend_function object
			fobj := make([]byte, vms.zend_function.Sizeof)
			// Set type to ZEND_USER_FUNCTION
			fobj[vms.zend_function.common_type] = ZEND_USER_FUNCTION
			// Set function name pointer (points to zend_string)
			binary.LittleEndian.PutUint64(
				fobj[vms.zend_function.common_funcname:], funcNameStrAddr)
			// Set scope pointer (points to zend_class_entry)
			if tt.hasScope {
				binary.LittleEndian.PutUint64(
					fobj[vms.zend_function.common_scope:], classEntryAddr)
			}
			// Set source filename pointer
			binary.LittleEndian.PutUint64(
				fobj[vms.zend_function.op_array_filename:], sourceFileStrAddr)
			// Set line start
			binary.LittleEndian.PutUint32(
				fobj[vms.zend_function.op_array_linestart:], 10)

			mem.writeAt(funcObjAddr, fobj)

			// Write function name zend_string (val is at offset 24)
			mem.writeString(funcNameStrAddr+uint64(vms.zend_string.val), tt.funcName)

			// Write class entry and class name if scope is set
			if tt.hasScope {
				// zend_class_entry.name is at offset 8, points to a zend_string
				mem.writeUint64(classEntryAddr+uint64(vms.zend_class_entry.name), classNameStrAddr)
				// Write class name zend_string
				mem.writeString(classNameStrAddr+uint64(vms.zend_string.val), tt.className)
			}

			// Write source file name
			mem.writeString(sourceFileStrAddr+uint64(vms.zend_string.val), "/app/test.php")

			// Create the phpInstance
			addrToFunction, err := freelru.New[libpf.Address, *phpFunction](
				interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
			require.NoError(t, err)

			instance := &phpInstance{
				d:              d,
				rm:             remotememory.RemoteMemory{ReaderAt: mem},
				addrToFunction: addrToFunction,
			}

			// Call getFunction
			f, err := instance.getFunction(libpf.Address(funcObjAddr), 0)
			require.NoError(t, err)
			require.NotNil(t, f)

			assert.Equal(t, tt.expectedFuncName, f.name.String())
		})
	}
}

func TestGetFunction_NullPointer(t *testing.T) {
	mem := newMockMemory()
	d := buildDefaultVMStructs()

	addrToFunction, err := freelru.New[libpf.Address, *phpFunction](
		interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
	require.NoError(t, err)

	instance := &phpInstance{
		d:              d,
		rm:             remotememory.RemoteMemory{ReaderAt: mem},
		addrToFunction: addrToFunction,
	}

	_, err = instance.getFunction(0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "null pointer")
}

func TestGetFunction_TopLevelCode(t *testing.T) {
	mem := newMockMemory()
	d := buildDefaultVMStructs()
	vms := &d.vmStructs

	const funcObjAddr = uint64(0x1000)

	// Build a zend_function with no name (simulates top-level code)
	fobj := make([]byte, vms.zend_function.Sizeof)
	fobj[vms.zend_function.common_type] = ZEND_USER_FUNCTION
	// funcname pointer is 0 (null) — no function name
	mem.writeAt(funcObjAddr, fobj)

	addrToFunction, err := freelru.New[libpf.Address, *phpFunction](
		interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
	require.NoError(t, err)

	instance := &phpInstance{
		d:              d,
		rm:             remotememory.RemoteMemory{ReaderAt: mem},
		addrToFunction: addrToFunction,
	}

	f, err := instance.getFunction(libpf.Address(funcObjAddr), ZEND_CALL_TOP_CODE)
	require.NoError(t, err)
	assert.Equal(t, interpreter.TopLevelFunctionName, f.name)
}
