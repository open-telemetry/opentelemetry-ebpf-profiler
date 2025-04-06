package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/golang"

import (
	"fmt"
	"regexp"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"

var goMajorMinorRegex = regexp.MustCompile(`^go\d+\.\d+`)

type data struct {
	goVersion string
	offsets   C.GoCustomLabelsOffsets
	interpreter.InstanceStubs
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if err := ebpf.UpdateProcData(libpf.Go, pid, unsafe.Pointer(&d.offsets)); err != nil {
		return nil, err
	}

	return &d, nil
}

func (d data) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.Go, pid)
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	// Note: So far we have observed that offsets are always the same for any
	// go1.mm.yy with fixed mm and any value of yy. That is; the major and minor
	// version determine the offsets, while the patch version has no effect.
	//
	// If this should change in some future Go patch release, we'll need to change
	// this function.

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
	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)
	majorMinor := goMajorMinorRegex.FindString(goVersion)
	if majorMinor == "" {
		return nil, fmt.Errorf("failed to parse go version %s into goM.mm", goVersion)
	}

	offsets, ok := allOffsets[majorMinor]
	if !ok {
		// If we don't know this version its probably a new version and the latest offsets
		// are our best bet.
		log.Warnf("version %s unknown; using offsets for latest known Go version %s."+
			"If Go traceID integration and other custom labels support is buggy,"+
			" try upgrading to the latest profiler version.", goVersion, latestVersion)
		return data{
			goVersion: goVersion,
			offsets:   allOffsets[latestVersion],
		}, nil
	}

	return data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {}
