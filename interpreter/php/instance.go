// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/ebpf-profiler/interpreter/php"

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
	"go.opentelemetry.io/ebpf-profiler/util"
)

//nolint:golint,stylecheck,revive
const (
	// zend_function.type definitions from PHP sources
	ZEND_USER_FUNCTION = (1 << 1)
	ZEND_EVAL_CODE     = (1 << 2)

	// This is used to check if the symbolized frame belongs to
	// top-level code.
	// From https://github.com/php/php-src/blob/PHP-8.0/Zend/zend_compile.h#L542
	ZEND_CALL_TOP_CODE = (1<<17 | 1<<16)
)

// phpFunction contains the information we cache for a corresponding
// PHP interpreter's zend_function structure.
type phpFunction struct {
	// name is the extracted name
	name string

	// sourceFileName is the extracted filename field
	sourceFileName string

	// fileID is the synthesized methodID
	fileID libpf.FileID

	// lineStart is the first source code line for this function
	lineStart uint32
}

type phpInstance struct {
	interpreter.InstanceStubs

	// PHP symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64
	// Failure count for finding the return address in execute_ex
	vmRTCount atomic.Uint64

	d  *phpData
	rm remotememory.RemoteMemory

	// addrToFunction maps a PHP Function object to a phpFunction which caches
	// the needed data from it.
	addrToFunction *freelru.LRU[libpf.Address, *phpFunction]
}

func (i *phpInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.PHP, pid)
}

func (i *phpInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToFuncStats := i.addrToFunction.ResetMetrics()

	return []metrics.Metric{
		{
			ID:    metrics.IDPHPSymbolizationSuccess,
			Value: metrics.MetricValue(i.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDPHPSymbolizationFailure,
			Value: metrics.MetricValue(i.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDPHPAddrToFuncHit,
			Value: metrics.MetricValue(addrToFuncStats.Hits),
		},
		{
			ID:    metrics.IDPHPAddrToFuncMiss,
			Value: metrics.MetricValue(addrToFuncStats.Misses),
		},
		{
			ID:    metrics.IDPHPAddrToFuncAdd,
			Value: metrics.MetricValue(addrToFuncStats.Inserts),
		},
		{
			ID:    metrics.IDPHPAddrToFuncDel,
			Value: metrics.MetricValue(addrToFuncStats.Removals),
		},
		{
			ID:    metrics.IDPHPFailedToFindReturnAddress,
			Value: metrics.MetricValue(i.vmRTCount.Swap(0)),
		},
	}, nil
}

func (i *phpInstance) getFunction(addr libpf.Address, typeInfo uint32) (*phpFunction, error) {
	if addr == 0 {
		return nil, errors.New("failed to read code object: null pointer")
	}
	if value, ok := i.addrToFunction.Get(addr); ok {
		return value, nil
	}

	vms := &i.d.vmStructs
	fobj := make([]byte, vms.zend_function.Sizeof)
	if err := i.rm.Read(addr, fobj); err != nil {
		return nil, fmt.Errorf("failed to read function object: %v", err)
	}

	// Parse the zend_function structure
	ftype := npsr.Uint8(fobj, vms.zend_function.common_type)
	fname := i.rm.String(npsr.Ptr(fobj, vms.zend_function.common_funcname) + vms.zend_string.val)

	if fname != "" && !util.IsValidString(fname) {
		log.Debugf("Extracted invalid PHP function name at 0x%x '%v'", addr, []byte(fname))
		fname = ""
	}

	if fname == "" {
		// If we're at the top-most scope then we can display that information.
		if typeInfo&ZEND_CALL_TOP_CODE > 0 {
			fname = interpreter.TopLevelFunctionName
		} else {
			fname = unknownFunctionName
		}
	}

	sourceFileName := ""
	lineStart := uint32(0)
	var lineBytes []byte
	switch ftype {
	case ZEND_USER_FUNCTION, ZEND_EVAL_CODE:
		sourceAddr := npsr.Ptr(fobj, vms.zend_function.op_array_filename)
		sourceFileName = i.rm.String(sourceAddr + vms.zend_string.val)
		if !util.IsValidString(sourceFileName) {
			log.Debugf("Extracted invalid PHP source file name at 0x%x '%v'",
				addr, []byte(sourceFileName))
			sourceFileName = ""
		}

		if ftype == ZEND_EVAL_CODE {
			fname = evalCodeFunctionName
			// To avoid duplication we get rid of the filename
			// It'll look something like "eval'd code", so no
			// information is lost here.
			sourceFileName = ""
		}

		lineStart = npsr.Uint32(fobj, vms.zend_function.op_array_linestart)
		//nolint:lll
		lineBytes = fobj[vms.zend_function.op_array_linestart : vms.zend_function.op_array_linestart+8]
	}

	// The fnv hash Write() method calls cannot fail, so it's safe to ignore the errors.
	h := fnv.New128a()
	_, _ = h.Write([]byte(sourceFileName))
	_, _ = h.Write([]byte(fname))
	_, _ = h.Write(lineBytes)
	fileID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create a file ID: %v", err)
	}

	pf := &phpFunction{
		name:           fname,
		sourceFileName: sourceFileName,
		fileID:         fileID,
		lineStart:      lineStart,
	}
	i.addrToFunction.Add(addr, pf)
	return pf, nil
}

func (i *phpInstance) Symbolize(symbolReporter reporter.SymbolReporter,
	frame *host.Frame, trace *libpf.Trace) error {
	// With Symbolize() in opcacheInstance there is a dedicated function to symbolize JITTed
	// PHP frames. But as we also attach phpInstance to PHP processes with JITTed frames, we
	// use this function to symbolize all PHP frames, as the process to do so is the same.
	if !frame.Type.IsInterpType(libpf.PHP) &&
		!frame.Type.IsInterpType(libpf.PHPJIT) {
		return interpreter.ErrMismatchInterpreterType
	}

	sfCounter := successfailurecounter.New(&i.successCount, &i.failCount)
	defer sfCounter.DefaultToFailure()

	funcPtr := libpf.Address(frame.File)
	// We pack type info and the line number into linenos
	typeInfo := uint32(frame.Lineno >> 32)
	line := frame.Lineno & 0xffffffff

	f, err := i.getFunction(funcPtr, typeInfo)
	if err != nil {
		return fmt.Errorf("failed to get php function %x: %v", funcPtr, err)
	}

	funcOff := uint32(0)
	if f.lineStart != 0 && libpf.AddressOrLineno(f.lineStart) <= line {
		funcOff = uint32(line) - f.lineStart
	}
	frameID := libpf.NewFrameID(f.fileID, line)
	trace.AppendFrameID(libpf.PHPFrame, frameID)
	symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
		FrameID:        frameID,
		FunctionName:   f.name,
		SourceFile:     f.sourceFileName,
		SourceLine:     libpf.SourceLineno(line),
		FunctionOffset: funcOff,
	})

	sfCounter.ReportSuccess()
	return nil
}
