package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/golang"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func getVersionSection(f *pfelf.File) io.ReaderAt {
	if sec := f.Section(".go.buildinfo"); sec != nil {
		return sec
	}
	for _, seg := range f.Progs {
		if seg.Type == elf.PT_LOAD && seg.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return &seg
		}
	}
	return nil
}

var ErrNoGoVersion = errors.New("go version not found")
var buildInfoMagic = []byte("\xff Go buildinf:")

// readBuildInfo reads build info, failing if it's not
// in the first 1 MiB of the given stream.
func readBuildInfo(s io.ReaderAt) ([]byte, error) {
	const (
		buildInfoAlign = 16
		buildInfoSize  = 32
		chunk          = 1 << 20
	)
	buf := make([]byte, chunk)
	n, err := s.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	data := buf[:n]
	for {
		i := bytes.Index(data, buildInfoMagic)
		if i < 0 || len(data)-i < buildInfoSize {
			break
		}
		if i%buildInfoAlign == 0 && len(data)-i >= buildInfoSize {
			data = data[i:]
			return data, nil
		}
		data = data[(i+buildInfoAlign-1)&^(buildInfoAlign-1):]
	}
	return nil, ErrNoGoVersion
}

func decodeString(data []byte) string {
	u, n := binary.Uvarint(data)
	if n <= 0 || u > uint64(len(data)-n) {
		return ""
	}
	return string(data[n : uint64(n)+u])
}

// readString returns the string at address addr in the executable x.
func readString(x *pfelf.File, ptrSize int,
	readPtr func([]byte) uint64, addr uint64) (string, error) {
	buf := make([]byte, 2*ptrSize)
	n, err := x.ReadAt(buf, int64(addr))
	if err != nil {
		return "", err
	}
	if n != len(buf) {
		return "", io.EOF
	}
	dataAddr := readPtr(buf)
	dataLen := readPtr(buf[ptrSize:])
	const maxSize = 64 // implausible that a Go version string is bigger than this
	if dataLen > maxSize {
		return "", ErrNoGoVersion
	}
	buf = make([]byte, dataLen)
	n, err = x.ReadAt(buf, int64(dataAddr))
	if err != nil {
		return "", err
	}
	if n != len(buf) {
		return "", io.EOF
	}
	return string(buf), nil
}

// ReadGoVersion returns the version of the Go toolchain that build the binary
// (for example, "go1.19.2").
//
// It is guaranteed not to consume more than 1 MiB of memory.
func ReadGoVersion(f *pfelf.File) (string, error) {
	vs := getVersionSection(f)
	if vs == nil {
		return "", ErrNoGoVersion
	}
	data, err := readBuildInfo(vs)
	if err != nil {
		return "", err
	}
	ptrSize := int(data[14])
	var vers string
	if data[15]&2 != 0 {
		vers = decodeString(data[32:])
	} else {
		bigEndian := data[15] != 0
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else if ptrSize == 8 {
			readPtr = bo.Uint64
		} else {
			return "", ErrNoGoVersion
		}
		vers, err = readString(f, ptrSize, readPtr, readPtr(data[16:]))
		if err != nil {
			return "", err
		}
	}
	return vers, nil
}
