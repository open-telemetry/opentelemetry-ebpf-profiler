//go:build !linux

// Package mmap is inspired by golang.org/x/exp/mmap with
// additional functionality.
package mmap // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"

import (
	"errors"
	"os"
)

func closeData(_ []byte) error {
	return nil
}

// OpenFile is a stub for non-Linux platforms.
func OpenFile(_ *os.File) (*ReaderAt, error) {
	return nil, errors.New("mmap: not supported on this platform")
}

func (r *ReaderAt) SetMadvDontNeed() error {
	return nil
}

func (r *ReaderAt) setRandom() error {
	return nil
}
