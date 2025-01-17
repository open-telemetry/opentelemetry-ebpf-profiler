// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/zeebo/xxh3"
)

// FrameID represents a frame as an address in an executable file
// or as a line in a source code file.
type FrameID struct {
	// fileID is the fileID of the frame
	fileID FileID

	// addressOrLineno is the address or lineno of the frame
	addressOrLineno AddressOrLineno
}

// NewFrameID creates a new FrameID from the fileId and address or line.
func NewFrameID(fileID FileID, addressOrLineno AddressOrLineno) FrameID {
	return FrameID{
		fileID:          fileID,
		addressOrLineno: addressOrLineno,
	}
}

// NewFrameIDFromString creates a new FrameID from its base64 string representation.
func NewFrameIDFromString(frameEncoded string) (FrameID, error) {
	var frameID FrameID

	bytes, err := base64.RawURLEncoding.DecodeString(frameEncoded)
	if err != nil {
		return frameID, fmt.Errorf("failed to decode frameID %v: %v", frameEncoded, err)
	}

	return NewFrameIDFromBytes(bytes)
}

// NewFrameIDFromBytes creates a new FrameID from a byte array of length 24.
func NewFrameIDFromBytes(bytes []byte) (FrameID, error) {
	var frameID FrameID
	var err error

	if len(bytes) != 24 {
		return frameID, fmt.Errorf("unexpected frameID size (expected 24 bytes): %d",
			len(bytes))
	}

	if frameID.fileID, err = FileIDFromBytes(bytes[0:16]); err != nil {
		return frameID, fmt.Errorf("failed to create fileID from bytes: %v", err)
	}

	frameID.addressOrLineno = AddressOrLineno(binary.BigEndian.Uint64(bytes[16:24]))

	return frameID, nil
}

// Hash32 returns a 32 bits hash of the input.
// It's main purpose is to be used as key for caching.
func (f FrameID) Hash32() uint32 {
	return uint32(f.Hash())
}

// String returns the base64 encoded representation.
func (f FrameID) String() string {
	return base64.RawURLEncoding.EncodeToString(f.Bytes())
}

// EncodeTo encodes the frame ID into the base64 encoded representation
// and stores it in the provided destination byte array.
// The length of the destination must be at least EncodedLen().
func (f FrameID) EncodeTo(dst []byte) {
	base64.RawURLEncoding.Encode(dst, f.Bytes())
}

// EncodedLen returns the length of the FrameID's base64 representation.
func (FrameID) EncodedLen() int {
	// FrameID is 24 bytes long, the base64 representation is one base64 byte per 6 bits.
	return ((16 + 8) * 8) / 6
}

// Bytes returns the frameid as byte sequence.
func (f FrameID) Bytes() []byte {
	// Using frameID := make([byte, 24]) here makes the function ~5% slower.
	var frameID [24]byte

	copy(frameID[:], f.fileID.Bytes())
	binary.BigEndian.PutUint64(frameID[16:], uint64(f.addressOrLineno))
	return frameID[:]
}

// Hash calculates a hash from the frameid.
// xxh3 is 4x faster than fnv.
func (f FrameID) Hash() uint64 {
	return xxh3.Hash(f.Bytes())
}

// FileID returns the fileID part of the frameID.
func (f FrameID) FileID() FileID {
	return f.fileID
}

// AddressOrLine returns the addressOrLine part of the frameID.
func (f FrameID) AddressOrLine() AddressOrLineno {
	return f.addressOrLineno
}

// AsIP returns the FrameID as a net.IP type to be used
// for the PC range in profiling-symbols-*.
func (f FrameID) AsIP() net.IP {
	bytes := f.Bytes()
	ip := make([]byte, 16)
	copy(ip[:8], bytes[:8])  // first 64bits of FileID
	copy(ip[8:], bytes[16:]) // addressOrLine
	return ip
}
