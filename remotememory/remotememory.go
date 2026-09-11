// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// remotememory provides access to memory space of a process. The ReaderAt
// interface is used for the basic access, and various convenience functions are
// provided to help reading specific data types. Accessors without a Read prefix
// fold a failed read into the zero value.
package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"

import (
	"bytes"
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// RemoteMemory implements a set of convenience functions to access the remote memory
type RemoteMemory struct {
	io.ReaderAt
	// Bias is the adjustment for pointers (used to unrelocate pointers in coredump)
	Bias libpf.Address
}

// Valid determines if this RemoteMemory instance contains a valid reference to target process
func (rm RemoteMemory) Valid() bool {
	return rm.ReaderAt != nil
}

// Read fills slice p[] with data from remote memory at address addr
func (rm RemoteMemory) Read(addr libpf.Address, p []byte) error {
	_, err := rm.ReadAt(p, int64(addr))
	return err
}

// readInt decodes in host byte order.
func readInt[T ~uint8 | ~uint16 | ~uint32 | ~uint64](
	rm RemoteMemory, addr libpf.Address,
) (T, error) {
	var v T
	if err := rm.Read(addr, pfunsafe.FromPointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

// ReadPtr reads a native pointer from remote memory
func (rm RemoteMemory) ReadPtr(addr libpf.Address) (libpf.Address, error) {
	v, err := readInt[uint64](rm, addr)
	if err != nil {
		return 0, err
	}
	return libpf.Address(v) - rm.Bias, nil
}

// ReadUint8 reads an 8-bit unsigned integer from remote memory
func (rm RemoteMemory) ReadUint8(addr libpf.Address) (uint8, error) {
	return readInt[uint8](rm, addr)
}

// ReadUint16 reads a 16-bit unsigned integer from remote memory
func (rm RemoteMemory) ReadUint16(addr libpf.Address) (uint16, error) {
	return readInt[uint16](rm, addr)
}

// ReadUint32 reads a 32-bit unsigned integer from remote memory
func (rm RemoteMemory) ReadUint32(addr libpf.Address) (uint32, error) {
	return readInt[uint32](rm, addr)
}

// ReadUint64 reads a 64-bit unsigned integer from remote memory
func (rm RemoteMemory) ReadUint64(addr libpf.Address) (uint64, error) {
	return readInt[uint64](rm, addr)
}

// Ptr reads a native pointer from remote memory
func (rm RemoteMemory) Ptr(addr libpf.Address) libpf.Address {
	v, _ := rm.ReadPtr(addr)
	return v
}

// Uint8 reads an 8-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint8(addr libpf.Address) uint8 {
	v, _ := readInt[uint8](rm, addr)
	return v
}

// Uint16 reads a 16-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint16(addr libpf.Address) uint16 {
	v, _ := readInt[uint16](rm, addr)
	return v
}

// Uint32 reads a 32-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint32(addr libpf.Address) uint32 {
	v, _ := readInt[uint32](rm, addr)
	return v
}

// Uint64 reads a 64-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint64(addr libpf.Address) uint64 {
	v, _ := readInt[uint64](rm, addr)
	return v
}

// String reads a zero terminated string from remote memory
func (rm RemoteMemory) String(addr libpf.Address) string {
	buf := make([]byte, 1024)
	n, err := rm.ReadAt(buf, int64(addr))
	if n == 0 || (err != nil && err != io.EOF) {
		return ""
	}
	buf = buf[:n]
	zeroIdx := bytes.IndexByte(buf, 0)
	if zeroIdx >= 0 {
		return string(buf[:zeroIdx])
	}
	if n != cap(buf) {
		return ""
	}

	bigBuf := make([]byte, 4096)
	copy(bigBuf, buf)
	n, err = rm.ReadAt(bigBuf[len(buf):], int64(addr)+int64(len(buf)))
	if n == 0 || (err != nil && err != io.EOF) {
		return ""
	}
	bigBuf = bigBuf[:len(buf)+n]
	zeroIdx = bytes.IndexByte(bigBuf, 0)
	if zeroIdx >= 0 {
		return string(bigBuf[:zeroIdx])
	}

	// Not a zero terminated string
	return ""
}

// StringPtr reads a zero terminate string by first dereferencing a string pointer
// from target memory
func (rm RemoteMemory) StringPtr(addr libpf.Address) string {
	addr = rm.Ptr(addr)
	if addr == 0 {
		return ""
	}
	return rm.String(addr)
}

// ProcessVirtualMemory implements ReaderAt by using process_vm_readv syscalls
// to read the remote memory.
type ProcessVirtualMemory struct {
	pid libpf.PID
}

// NewProcessVirtualMemory returns RemoteMemory with ProcessVirtualMemory as the underlying reader
func NewProcessVirtualMemory(pid libpf.PID) RemoteMemory {
	return RemoteMemory{ReaderAt: ProcessVirtualMemory{pid}}
}
