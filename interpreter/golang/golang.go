package golang

import (
	"errors"
	"fmt"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/remotememory"
	"github.com/elastic/otel-profiling-agent/util"
)

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"

type data struct {
	goVersion string
	offsets   C.GoCustomLabelsOffsets
	interpreter.InstanceStubs
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid util.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {

	if err := ebpf.UpdateProcData(libpf.Go, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}

	return &d, nil
}

func (d data) Detach(ebpf interpreter.EbpfHandler, pid util.PID) error {
	return ebpf.DeleteProcData(libpf.Go, pid)
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	file, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	goVersion, err := ReadGoVersion(file)
	if errors.Is(err, ErrNoGoVersion) {
		log.Debugf("file %s is not a Go binary", info.FileName())
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)

	offsets, ok := allOffsets[goVersion]
	if !ok {
		return nil, fmt.Errorf("no offsets found for go version %s", goVersion)
	}

	return data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}
