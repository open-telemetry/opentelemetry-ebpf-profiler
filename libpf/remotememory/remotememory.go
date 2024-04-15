/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// remotememory provides access to memory space of a process. The ReaderAt
// interface is used for the basic access, and various convenience functions are
// provided to help reading specific data types.
package remotememory

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/libpf"
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

// Ptr reads a native pointer from remote memory
func (rm RemoteMemory) Ptr(addr libpf.Address) libpf.Address {
	var buf [8]byte
	if rm.Read(addr, buf[:]) != nil {
		return 0
	}
	return libpf.Address(binary.LittleEndian.Uint64(buf[:])) - rm.Bias
}

// Uint8 reads an 8-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint8(addr libpf.Address) uint8 {
	var buf [1]byte
	if rm.Read(addr, buf[:]) != nil {
		return 0
	}
	return buf[0]
}

// Uint16 reads a 16-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint16(addr libpf.Address) uint16 {
	var buf [2]byte
	if rm.Read(addr, buf[:]) != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(buf[:])
}

// Uint32 reads a 32-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint32(addr libpf.Address) uint32 {
	var buf [4]byte
	if rm.Read(addr, buf[:]) != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(buf[:])
}

// Uint64 reads a 64-bit unsigned integer from remote memory
func (rm RemoteMemory) Uint64(addr libpf.Address) uint64 {
	var buf [8]byte
	if rm.Read(addr, buf[:]) != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:])
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

// RecordingReader allows reading data from the remote process using io.ReadByte interface.
// It provides basic buffering by reading memory in pieces of 'chunk' bytes and it also
// records all read memory in a backing buffer to be later stored as a whole.
type RecordingReader struct {
	// rm is the RemoteMemory from which we are reading the data from
	rm *RemoteMemory
	// buf contains all data read from the target process
	buf []byte
	// addr is the target virtual address to continue reading from
	addr libpf.Address
	// i is the index to the buf[] byte which is to be returned next in ReadByte()
	i int
	// chunk is the number of bytes to read from target process when mora data is needed
	chunk int
}

// ReadByte implements io.ByteReader interface to read memory single byte at a time.
func (rr *RecordingReader) ReadByte() (byte, error) {
	// Readahead to buffer if needed
	if rr.i >= len(rr.buf) {
		buf := make([]byte, len(rr.buf)+rr.chunk)
		copy(buf, rr.buf)
		err := rr.rm.Read(rr.addr, buf[len(rr.buf):])
		if err != nil {
			return 0, err
		}
		rr.addr += libpf.Address(rr.chunk)
		rr.buf = buf
	}
	// Return byte from buffer
	b := rr.buf[rr.i]
	rr.i++
	return b, nil
}

// GetBuffer returns all the data so far as a single slice.
func (rr *RecordingReader) GetBuffer() []byte {
	return rr.buf[0:rr.i]
}

// Reader returns a RecordingReader to read and record data from given start.
func (rm RemoteMemory) Reader(addr libpf.Address, chunkSize uint) *RecordingReader {
	return &RecordingReader{
		rm:    &rm,
		addr:  addr,
		chunk: int(chunkSize),
	}
}

// ProcessVirtualMemory implements RemoteMemory by using process_vm_readv syscalls
// to read the remote memory.
type ProcessVirtualMemory struct {
	pid libpf.PID
}

func (vm ProcessVirtualMemory) ReadAt(p []byte, off int64) (int, error) {
	numBytesWanted := len(p)
	if numBytesWanted == 0 {
		return 0, nil
	}
	localIov := []unix.Iovec{{Base: &p[0], Len: uint64(numBytesWanted)}}
	remoteIov := []unix.RemoteIovec{{Base: uintptr(off), Len: numBytesWanted}}
	numBytesRead, err := unix.ProcessVMReadv(int(vm.pid), localIov, remoteIov, 0)
	if err != nil {
		err = fmt.Errorf("failed to read PID %v at 0x%x: %w", vm.pid, off, err)
	} else if numBytesRead != numBytesWanted {
		err = fmt.Errorf("failed to read PID %v at 0x%x: got only %d of %d",
			vm.pid, off, numBytesRead, numBytesWanted)
	}
	return numBytesRead, err
}

// NewRemoteMemory returns ProcessVirtualMemory implementation of RemoteMemory.
func NewProcessVirtualMemory(pid libpf.PID) RemoteMemory {
	return RemoteMemory{ReaderAt: ProcessVirtualMemory{pid}}
}
