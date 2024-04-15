/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package php

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"regexp"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/freelru"
	npsr "github.com/elastic/otel-profiling-agent/libpf/nopanicslicereader"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/remotememory"
	"github.com/elastic/otel-profiling-agent/libpf/successfailurecounter"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/support"

	log "github.com/sirupsen/logrus"
)

// #include "../../support/ebpf/types.h"
import "C"

// zend_function.type definitions from PHP sources
// nolint:golint,stylecheck,revive
const (
	ZEND_USER_FUNCTION = (1 << 1)
	ZEND_EVAL_CODE     = (1 << 2)
)

// nolint:golint,stylecheck,revive
const (
	// This is used to check if the VM mode is the default one
	// From https://github.com/php/php-src/blob/PHP-8.0/Zend/zend_vm_opcodes.h#L29
	ZEND_VM_KIND_HYBRID = (1 << 2)

	// This is used to check if the symbolized frame belongs to
	// top-level code.
	// From https://github.com/php/php-src/blob/PHP-8.0/Zend/zend_compile.h#L542
	ZEND_CALL_TOP_CODE = (1<<17 | 1<<16)
)

const (
	// maxPHPRODataSize is the maximum PHP RO Data segment size to scan
	// (currently the largest seen is about 9M)
	maxPHPRODataSize = 16 * 1024 * 1024

	// unknownFunctionName is the name to be used when it cannot be read from the
	// interpreter, or explicit function name does not exist (global code not in function)
	unknownFunctionName = "<unknown>"

	// evalCodeFunctionName is a placeholder name to show that code has been evaluated
	// using eval in PHP.
	evalCodeFunctionName = "<eval'd code>"
)

var (
	// regex for the interpreter executable
	phpRegex     = regexp.MustCompile(".*/php(-cgi|-fpm)?[0-9.]*$|^php(-cgi|-fpm)?[0-9.]*$")
	versionMatch = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &php7Data{}
	_ interpreter.Instance = &php7Instance{}
)

type php7Data struct {
	version uint

	// egAddr is the `executor_globals` symbol value which is needed by the eBPF
	// program to build php backtraces.
	egAddr libpf.Address

	// rtAddr is the `return address` for the JIT code (in Hybrid mode).
	// This is described in more detail in the PHP unwinding doc,
	// but the short description is that PHP call stacks don't always
	// store return addresses.
	rtAddr libpf.Address

	// vmStructs reflects the PHP internal class names and the offsets of named field
	// nolint:golint,stylecheck,revive
	vmStructs struct {
		// https://github.com/php/php-src/blob/PHP-7.4/Zend/zend_globals.h#L135
		zend_executor_globals struct {
			current_execute_data uint
		}
		// https://github.com/php/php-src/blob/PHP-7.4/Zend/zend_compile.h#L503
		zend_execute_data struct {
			opline, function  uint
			this_type_info    uint
			prev_execute_data uint
		}
		// https://github.com/php/php-src/blob/PHP-7.4/Zend/zend_compile.h#L483
		zend_function struct {
			common_type, common_funcname          uint
			op_array_filename, op_array_linestart uint
			Sizeof                                uint
		}
		// https://github.com/php/php-src/blob/PHP-7.4/Zend/zend_types.h#L235
		zend_string struct {
			val libpf.Address
		}
		// https://github.com/php/php-src/blob/PHP-7.4/Zend/zend_compile.h#L136
		zend_op struct {
			lineno uint
		}
	}
}

type php7Instance struct {
	interpreter.InstanceStubs

	// PHP symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64
	// Failure count for finding the return address in execute_ex
	vmRTCount atomic.Uint64

	d  *php7Data
	rm remotememory.RemoteMemory

	// addrToFunction maps a PHP Function object to a phpFunction which caches
	// the needed data from it.
	addrToFunction *freelru.LRU[libpf.Address, *phpFunction]
}

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

	// lineSeen is a set of line numbers we have already seen and symbolized
	lineSeen libpf.Set[libpf.AddressOrLineno]
}

func (i *php7Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.PHP, pid)
}

func (i *php7Instance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToFuncStats := i.addrToFunction.GetAndResetStatistics()

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
			Value: metrics.MetricValue(addrToFuncStats.Hit),
		},
		{
			ID:    metrics.IDPHPAddrToFuncMiss,
			Value: metrics.MetricValue(addrToFuncStats.Miss),
		},
		{
			ID:    metrics.IDPHPAddrToFuncAdd,
			Value: metrics.MetricValue(addrToFuncStats.Added),
		},
		{
			ID:    metrics.IDPHPAddrToFuncDel,
			Value: metrics.MetricValue(addrToFuncStats.Deleted),
		},
		{
			ID:    metrics.IDPHPFailedToFindReturnAddress,
			Value: metrics.MetricValue(i.vmRTCount.Swap(0)),
		},
	}, nil
}

func (i *php7Instance) getFunction(addr libpf.Address, typeInfo uint32) (*phpFunction, error) {
	if addr == 0 {
		return nil, fmt.Errorf("failed to read code object: null pointer")
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

	if fname != "" && !libpf.IsValidString(fname) {
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
		if !libpf.IsValidString(sourceFileName) {
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
		// nolint:lll
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
		lineSeen:       make(libpf.Set[libpf.AddressOrLineno]),
	}
	i.addrToFunction.Add(addr, pf)
	return pf, nil
}

func (i *php7Instance) Symbolize(symbolReporter reporter.SymbolReporter,
	frame *host.Frame, trace *libpf.Trace) error {
	// With Symbolize() in opcacheInstance there is a dedicated function to symbolize JITTed
	// PHP frames. But as we also attach php7Instance to PHP processes with JITTed frames, we
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

	trace.AppendFrame(libpf.PHPFrame, f.fileID, line)

	if _, ok := f.lineSeen[line]; ok {
		return nil
	}

	funcOff := uint32(0)
	if f.lineStart != 0 && libpf.AddressOrLineno(f.lineStart) <= line {
		funcOff = uint32(line) - f.lineStart
	}
	symbolReporter.FrameMetadata(
		f.fileID, line, libpf.SourceLineno(line), funcOff,
		f.name, f.sourceFileName)

	f.lineSeen[line] = libpf.Void{}

	log.Debugf("[%d] [%x] %v+%v at %v:%v",
		len(trace.FrameTypes),
		f.fileID, f.name, funcOff,
		f.sourceFileName, line)

	sfCounter.ReportSuccess()
	return nil
}

func (d *php7Data) String() string {
	ver := d.version
	return fmt.Sprintf("PHP %d.%d.%d", (ver>>16)&0xff, (ver>>8)&0xff, ver&0xff)
}

func (d *php7Data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	addrToFunction, err :=
		freelru.New[libpf.Address, *phpFunction](interpreter.LruFunctionCacheSize,
			libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	vms := &d.vmStructs
	data := C.PHPProcInfo{
		current_execute_data: C.u64(d.egAddr+bias) +
			C.u64(vms.zend_executor_globals.current_execute_data),
		jit_return_address:                  C.u64(d.rtAddr + bias),
		zend_execute_data_function:          C.u8(vms.zend_execute_data.function),
		zend_execute_data_opline:            C.u8(vms.zend_execute_data.opline),
		zend_execute_data_prev_execute_data: C.u8(vms.zend_execute_data.prev_execute_data),
		zend_execute_data_this_type_info:    C.u8(vms.zend_execute_data.this_type_info),
		zend_function_type:                  C.u8(vms.zend_function.common_type),
		zend_op_lineno:                      C.u8(vms.zend_op.lineno),
	}
	if err := ebpf.UpdateProcData(libpf.PHP, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}

	instance := &php7Instance{
		d:              d,
		rm:             rm,
		addrToFunction: addrToFunction,
	}

	// If we failed to find the return address we need to increment
	// the value here. This happens once per interpreter instance,
	// but tracking it will help debugging later.
	if d.rtAddr == 0 && d.version >= 0x080000 {
		instance.vmRTCount.Store(1)
	}

	return instance, nil
}

func VersionExtract(rodata string) (uint, error) {
	matches := versionMatch.FindStringSubmatch(rodata)
	if matches == nil {
		return 0, fmt.Errorf("no valid PHP version string found")
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	release, _ := strconv.Atoi(matches[3])
	return uint(major*0x10000 + minor*0x100 + release), nil
}

func determinePHPVersion(ef *pfelf.File) (uint, error) {
	// There is no ideal way to get the PHP version. This just searches
	// for a known string with the version number from .rodata.
	if ef.ROData == nil {
		return 0, fmt.Errorf("no RO data")
	}

	needle := []byte("X-Powered-By: PHP/")
	for _, segment := range ef.ROData {
		rodata, err := segment.Data(maxPHPRODataSize)
		if err != nil {
			return 0, err
		}
		idx := bytes.Index(rodata, needle)
		if idx < 0 {
			continue
		}

		idx += len(needle)
		zeroIdx := bytes.IndexByte(rodata[idx:], 0)
		if zeroIdx < 0 {
			continue
		}
		version, err := VersionExtract(string(rodata[idx : idx+zeroIdx]))
		if err != nil {
			continue
		}
		return version, nil
	}

	return 0, fmt.Errorf("no segment contained X-Powered-By")
}

func recoverExecuteExJumpLabelAddress(ef *pfelf.File) (libpf.SymbolValue, error) {
	// This function recovers the return address for JIT'd PHP code by
	// disassembling the execute_ex function. This is entirely heuristic and
	// described in some detail in the PHP8 unwinding document in the "disassembling
	// execute_ex" section. This is only useful for PHP8+

	// Zend/zend_vm_execute.h: execute_ex(zend_execute_data *ex) is the main VM
	// executor function, has been such at least since PHP7.0. This is guaranteed
	// to be the vm executor function in PHP JIT'd code, since the JIT is (currently)
	// inoperable with overridden execute_ex's
	executeExAddr, err := ef.LookupSymbolAddress("execute_ex")
	if err != nil {
		return libpf.SymbolValueInvalid,
			fmt.Errorf("could not find execute_ex: %w", err)
	}

	// The address we care about varies from being 47 bytes in to about 107 bytes in,
	// so we'll read 128 bytes. This might need to be adjusted up in future.
	code := make([]byte, 128)
	if _, err = ef.ReadVirtualMemory(code, int64(executeExAddr)); err != nil {
		return libpf.SymbolValueInvalid,
			fmt.Errorf("could not read from executeExAddr: %w", err)
	}

	returnAddress, err := retrieveExecuteExJumpLabelAddressWrapper(code, executeExAddr)
	if err != nil {
		return libpf.SymbolValueInvalid,
			fmt.Errorf("reading the return address from execute_ex failed (%w)",
				err)
	}

	return returnAddress, nil
}

func determineVMKind(ef *pfelf.File) (uint, error) {
	// This function recovers the PHP VM mode from the PHP binary
	// This is a compile-time configuration option that configures
	// how the PHP VM calls functions. This is only useful for PHP8+

	// This is a publicly exposed function in PHP that returns the VM type
	// This has been implemented in PHP since at least 7.2
	vmKindAddr, err := ef.LookupSymbolAddress("zend_vm_kind")
	if err != nil {
		return 0, fmt.Errorf("zend_vm_kind not found: %w", err)
	}

	// We should only need around 32 bytes here, since this function should be
	// really short (e.g a mov and a ret).
	code := make([]byte, 32)
	if _, err = ef.ReadVirtualMemory(code, int64(vmKindAddr)); err != nil {
		return 0, fmt.Errorf("could not read from zend_vm_kind: %w", err)
	}

	vmKind, err := retrieveZendVMKindWrapper(code)
	if err != nil {
		return 0, fmt.Errorf("an error occurred decoding zend_vm_kind: %w", err)
	}

	return vmKind, nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !phpRegex.MatchString(info.FileName()) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	version, err := determinePHPVersion(ef)
	if err != nil {
		return nil, err
	}

	// Only tested on PHP7.3-PHP8.1. Other similar versions probably only require
	// tweaking the offsets.
	const minVer, maxVer = 0x070300, 0x080300
	if version < minVer || version >= maxVer {
		return nil, fmt.Errorf("PHP version %d.%d.%d (need >= %d.%d and < %d.%d)",
			(version>>16)&0xff, (version>>8)&0xff, version&0xff,
			(minVer>>16)&0xff, (minVer>>8)&0xff,
			(maxVer>>16)&0xff, (maxVer>>8)&0xff)
	}

	egAddr, err := ef.LookupSymbolAddress("executor_globals")
	if err != nil {
		return nil, fmt.Errorf("PHP %x: executor_globals not found: %v", version, err)
	}

	// Zend/zend_vm_execute.h: execute_ex(zend_execute_data *ex) is the main VM
	// executor function, has been such at least since PHP7.0.
	interpRanges, err := info.GetSymbolAsRanges("execute_ex")
	if err != nil {
		return nil, err
	}

	// If the version is PHP8+ we need to be able to
	// potentially unwind JIT code. For now we need to recover
	// the return address and check that hybrid mode is used. This is the
	// default mode (there are others but they should be rarely used in production)
	// Note that if there is an error in the block below then unwinding will produce
	// incomplete stack unwindings if the JIT compiler is used.
	rtAddr := libpf.SymbolValueInvalid
	if version >= 0x080000 {
		var vmKind uint
		vmKind, err = determineVMKind(ef)
		if err != nil {
			log.Debugf("PHP version %x: an error occurred while determining "+
				"the VM kind (%v)",
				version, err)
		} else if vmKind == ZEND_VM_KIND_HYBRID {
			rtAddr, err = recoverExecuteExJumpLabelAddress(ef)
			if err != nil {
				log.Debugf("PHP version %x: an error occurred while determining "+
					"the return address for execute_ex: (%v)", version, err)
			}
		}
	}
	pid := &php7Data{
		version: version,
		egAddr:  libpf.Address(egAddr),
		rtAddr:  libpf.Address(rtAddr),
	}

	// PHP does not provide introspection data, hard code the struct field
	// offsets based on detected version. Some values can be fairly easily
	// calculated from the struct definitions, but some are looked up by
	// using gdb and getting the field offset directly from debug data.
	vms := &pid.vmStructs
	vms.zend_executor_globals.current_execute_data = 488
	vms.zend_execute_data.opline = 0
	vms.zend_execute_data.function = 24
	vms.zend_execute_data.this_type_info = 40
	vms.zend_execute_data.prev_execute_data = 48
	vms.zend_function.common_type = 0
	vms.zend_function.common_funcname = 8
	vms.zend_function.op_array_filename = 128
	vms.zend_function.op_array_linestart = 136
	// Note: the sizeof here isn't actually the sizeof the
	// zend_function object. This is set to 168
	// primarily for efficiency reasons, since we
	// need at most 168 bytes.
	vms.zend_function.Sizeof = 168
	vms.zend_string.val = 24
	vms.zend_op.lineno = 24
	if version >= 0x080200 {
		vms.zend_function.op_array_filename = 152
		vms.zend_function.op_array_linestart = 160
	} else if version >= 0x080000 {
		vms.zend_function.op_array_filename = 144
		vms.zend_function.op_array_linestart = 152
	} else if version >= 0x070400 {
		vms.zend_function.op_array_filename = 136
		vms.zend_function.op_array_linestart = 144
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindPHP,
		info.FileID(), interpRanges); err != nil {
		return nil, err
	}

	return pid, nil
}
