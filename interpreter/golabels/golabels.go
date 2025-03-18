// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"fmt"
	"go/version"
	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// #include "../../support/ebpf/types.h"
import "C"

type data struct {
	goVersion string
	offsets   C.GoLabelsOffsets
	interpreter.InstanceStubs
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if err := ebpf.UpdateProcData(libpf.GoLabels, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *data) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.GoLabels, pid)
}

func (d *data) Unload(_ interpreter.EbpfHandler) {}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	file, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	goVersion, err := file.GoVersion()
	if err != nil {
		return nil, err
	}
	if goVersion == "" {
		log.Debugf("file %s is not a Go binary", info.FileName())
		return nil, nil
	}

	if version.Compare(goVersion, "go1.25") >= 0 {
		return nil, fmt.Errorf("unsupported Go version %s (need >= 1.13 and <= 1.24)", goVersion)
	}

	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)

	iscgo, err := file.IsCgoEnabled()
	if err != nil {
		return nil, err
	}
	offsets := getOffsets(goVersion)
	switch runtime.GOARCH {
	case "amd64":
		// https://github.com/golang/go/blob/396a48bea6f/src/cmd/compile/internal/amd64/ssa.go#L174
		offsets.tls_offset = -8
	case "arm64":
		// https://github.com/golang/go/blob/6885bad7dd86880be/src/runtime/tls_arm64.s#L11
		//  Get's compiled into:
		//  0x000000000007f260 <+0>:     adrp    x27, 0x1c2000 <runtime.mheap_+101440>
		//  0x000000000007f264 <+4>:     ldrsb   x0, [x27, #284]
		//  0x000000000007f268 <+8>:     cbz     x0, 0x7f278 <runtime.load_g+24>
		//  0x000000000007f26c <+12>:    mrs     x0, tpidr_el0
		//  0x000000000007f270 <+16>:    mov     x27, #0x30                      // #48
		//  0x000000000007f274 <+20>:    ldr     x28, [x0, x27]
		//  0x000000000007f278 <+24>:    ret
		if iscgo {
			offsets.tls_offset = 0x30
		}
	}

	return &data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}
