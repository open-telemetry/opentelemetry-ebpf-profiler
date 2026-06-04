// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file implements Reference which opens and caches a File on demand.

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

// Reference is a reference to an ELF file which is loaded and cached on demand.
type Reference struct {
	// ELFOpener opens auxiliary files by name (e.g. debuglink targets). When
	// open is nil it also opens the reference's own file via OpenELF(fileName).
	ELFOpener

	// fileName is the full path of the ELF to open.
	fileName string

	// open, when non-nil, opens the reference's own file instead of
	// ELFOpener.OpenELF(fileName). It lets callers inject context that a bare
	// filename cannot carry, e.g. a memory mapping.
	open func() (*File, error)

	// elfFile contains the cached ELF file
	elfFile *File
}

// NewReference returns a Reference that opens both its own file and any
// auxiliary files (e.g. debuglink targets) through elfOpener, by name.
func NewReference(fileName string, elfOpener ELFOpener) *Reference {
	return &Reference{fileName: fileName, ELFOpener: elfOpener}
}

// NewReferenceWithOpenFunc returns a Reference that opens its own file via
// open, while auxiliary files (e.g. debuglink targets) are still opened by
// name through elfOpener.
func NewReferenceWithOpenFunc(fileName string, elfOpener ELFOpener,
	open func() (*File, error),
) *Reference {
	return &Reference{fileName: fileName, ELFOpener: elfOpener, open: open}
}

// FileName returns the file name associated with this Reference
func (ref *Reference) FileName() string {
	return ref.fileName
}

// GetELF returns the File to access this File and keeps it cached. The
// caller of this functions must not Close the File.
func (ref *Reference) GetELF() (*File, error) {
	var err error
	if ref.elfFile == nil {
		if ref.open != nil {
			ref.elfFile, err = ref.open()
		} else {
			ref.elfFile, err = ref.OpenELF(ref.fileName)
		}
	}
	return ref.elfFile, err
}

// Close closes the File if it has been opened earlier.
func (ref *Reference) Close() {
	if ref.elfFile != nil {
		_ = ref.elfFile.Close()
		ref.elfFile = nil
	}
}
