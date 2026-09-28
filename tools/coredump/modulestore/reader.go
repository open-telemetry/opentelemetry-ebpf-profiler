// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package modulestore // import "go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"

import (
	"io"
	"io/fs"
	"time"
)

// ModuleReader allows reading a module from the module store. It implements
// fs.File and io.ReaderAt.
type ModuleReader struct {
	io.ReaderAt
	io.Closer
	name              string
	preferredReadSize uint
	size              uint
	offset            int64
}

var _ fs.File = &ModuleReader{}

// PreferredReadSize returns the preferred size and alignment of reads on this reader.
func (m *ModuleReader) PreferredReadSize() uint {
	return m.preferredReadSize
}

// Size returns the uncompressed size of the module.
func (m *ModuleReader) Size() uint {
	return m.size
}

// Read implements io.Reader by reading sequentially via ReadAt.
func (m *ModuleReader) Read(p []byte) (int, error) {
	if m.offset >= int64(m.size) {
		return 0, io.EOF
	}
	if remaining := int64(m.size) - m.offset; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := m.ReadAt(p, m.offset)
	m.offset += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

// Stat implements fs.File.
func (m *ModuleReader) Stat() (fs.FileInfo, error) {
	return moduleInfo{m}, nil
}

// moduleInfo implements fs.FileInfo for a ModuleReader.
type moduleInfo struct {
	m *ModuleReader
}

func (i moduleInfo) Name() string       { return i.m.name }
func (i moduleInfo) Size() int64        { return int64(i.m.size) }
func (i moduleInfo) Mode() fs.FileMode  { return 0o444 }
func (i moduleInfo) ModTime() time.Time { return time.Time{} }
func (i moduleInfo) IsDir() bool        { return false }
func (i moduleInfo) Sys() any           { return nil }
