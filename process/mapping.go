// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This file implements helpers to access a mapping's backing file through a
// Process's fs.FS, plus the optional capabilities a Process implementation
// may additionally provide for more precise or cheaper handling.

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"errors"
	"io"
	"io/fs"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// MappingFileOpener is an optional capability of a Process that can open a
// mapping's backing file more precisely than by path alone, e.g. via
// /proc/pid/map_files, which stays valid even after the file has been
// deleted or replaced on disk. Implementations should return an error
// satisfying errors.Is(err, ErrMappingFileUnavailable) when they have no
// precise route available, so OpenMapping falls back to opening the
// mapping's path.
type MappingFileOpener interface {
	OpenMapping(*RawMapping) (fs.File, error)
}

// MappingFileIDCalculator is an optional capability of a Process that needs
// to compute a mapping's FileID itself instead of hashing the content
// returned by OpenMapping, e.g. because the real file content isn't fully
// available (coredumps) or because a cheaper/cached computation exists
// (VDSO).
type MappingFileIDCalculator interface {
	CalculateMappingFileID(*RawMapping) (libpf.FileID, error)
}

// OpenMapping opens the backing file for a file-backed mapping through pr,
// using pr's MappingFileOpener capability if present and otherwise opening
// the mapping's path through pr's fs.FS.
func OpenMapping(pr Process, m *RawMapping) (fs.File, error) {
	if !m.IsFileBacked() {
		return nil, errors.New("no backing file for anonymous memory")
	}
	if mo, ok := pr.(MappingFileOpener); ok {
		f, err := mo.OpenMapping(m)
		if err == nil || !errors.Is(err, ErrMappingFileUnavailable) {
			return f, err
		}
	}
	return pr.Open(m.Path)
}

// MappingFileID calculates the FileID for a mapping's backing file, using
// pr's MappingFileIDCalculator capability if present and otherwise hashing
// the content returned by OpenMapping.
func MappingFileID(pr Process, m *RawMapping) (libpf.FileID, error) {
	if fc, ok := pr.(MappingFileIDCalculator); ok {
		return fc.CalculateMappingFileID(m)
	}
	f, err := OpenMapping(pr, m)
	if err != nil {
		return libpf.FileID{}, err
	}
	defer f.Close()
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return libpf.FileID{}, errors.New("mapping file does not support io.ReadSeeker")
	}
	return libpf.FileIDFromExecutableReader(rs)
}

// MappingLastModified returns the timestamp when the mapping's backing file
// was last modified, or zero if it cannot be determined.
func MappingLastModified(pr Process, m *RawMapping) int64 {
	f, err := OpenMapping(pr, m)
	if err != nil {
		return 0
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return st.ModTime().UnixNano()
}

// NewFile adapts a ReadAtCloser (e.g. a modulestore reader, or a coredump's
// in-memory file) into an fs.File for use as a Process's fs.FS Open result.
// Stat is a stub returning an error: the wrapped sources don't have a
// meaningful modification time.
func NewFile(rac pfelf.ReadAtCloser) fs.File {
	return &readerAtFile{ReadAtCloser: rac}
}

type readerAtFile struct {
	pfelf.ReadAtCloser
	off int64
}

func (f *readerAtFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.off)
	f.off += int64(n)
	return n, err
}

func (*readerAtFile) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat not supported")
}
