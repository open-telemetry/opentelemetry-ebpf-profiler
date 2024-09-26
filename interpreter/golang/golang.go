package golang

import (
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/interpreter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/remotememory"
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
	goVersion, err := ReadGoVersion(file)
	if errors.Is(err, ErrNoGoVersion) {
		log.Debugf("file %s is not a Go binary", info.FileName())
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)
	majorMinor := goMajorMinorRegex.FindString(goVersion)
	if majorMinor == "" {
		return nil, fmt.Errorf("failed to parse go version %s into goM.mm", goVersion)
	}

	offsets, ok := allOffsets[majorMinor]
	if !ok {
		// Info instead of warn: this is often going to be fine,
		// as the offsets tend not to change every release cycle.
		//
		// TODO: Reword the message if we upstream this,
		// since it mentions `parca-agent` by name.
		log.Infof("version %s unknown; using offsets for latest known Go version %s."+
			"If Go traceID integration and other custom labels support is buggy,"+
			" try upgrading parca-agent to the latest version.", goVersion, defaultVersion)
		return data{
			goVersion: goVersion,
			offsets:   allOffsets[defaultVersion],
		}, nil
	}

	return data{
		goVersion: goVersion,
		offsets:   offsets,
	}, nil
}
