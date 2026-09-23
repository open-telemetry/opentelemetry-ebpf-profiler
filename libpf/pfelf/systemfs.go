// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file implements an fs.FS that opens files directly from the local file system.

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"io/fs"
	"os"
)

// systemFS implements fs.FS by opening files directly from the local file system,
// without any process or sysroot scoping.
type systemFS struct{}

func (systemFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

// SystemFS opens files directly from the local file system.
var SystemFS fs.FS = systemFS{}
