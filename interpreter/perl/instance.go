/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package perl

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/metrics"
	npsr "github.com/elastic/otel-profiling-agent/nopanicslicereader"
	"github.com/elastic/otel-profiling-agent/remotememory"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/successfailurecounter"
	"github.com/elastic/otel-profiling-agent/tpbase"
	"github.com/elastic/otel-profiling-agent/util"
)

// #include "../../support/ebpf/types.h"
import "C"

type perlInstance struct {
	interpreter.InstanceStubs

	// Symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	d    *perlData
	rm   remotememory.RemoteMemory
	bias C.u64

	// addrToHEK maps a PERL Hash Element Key (string with hash) to a Go string
	addrToHEK *freelru.LRU[libpf.Address, string]

	// addrToCOP maps a PERL Control OP (COP) structure to a perlCOP which caches data from it
	addrToCOP *freelru.LRU[copKey, *perlCOP]

	// addrToGV maps a PERL Glob Value (GV) aka "symbol" to its name string
	addrToGV *freelru.LRU[libpf.Address, string]

	// memPool provides pointers to byte arrays for efficient memory reuse.
	memPool sync.Pool

	// hekLen is the largest number we did see in the last reporting interval for hekLen
	// in getHEK.
	hekLen atomic.Uint32

	// procInfoInserted tracks whether we've already inserted process info into BPF maps.
	procInfoInserted bool
}

// perlCOP contains information about Perl Control OPS structure
type perlCOP struct {
	fileID         libpf.FileID
	sourceFileName string
	line           libpf.AddressOrLineno
}

// copKey is used as cache key for Perl Control OPS structures.
type copKey struct {
	copAddr  libpf.Address
	funcName string
}

// hashCopKey returns a 32 bits hash of the input.
// It's main purpose is to hash keys for caching perlCOP values.
func hashCOPKey(k copKey) uint32 {
	h := k.copAddr.Hash()
	return uint32(h ^ xxhash.Sum64String(k.funcName))
}

func (i *perlInstance) UpdateTSDInfo(ebpf interpreter.EbpfHandler, pid util.PID,
	tsdInfo tpbase.TSDInfo) error {
	d := i.d
	stateInTSD := C.u8(0)
	if d.stateInTSD {
		stateInTSD = 1
	}
	vms := &d.vmStructs
	data := C.PerlProcInfo{
		version:    C.uint(d.version),
		stateAddr:  C.u64(d.stateAddr) + i.bias,
		stateInTSD: stateInTSD,

		tsdInfo: C.TSDInfo{
			offset:     C.s16(tsdInfo.Offset),
			multiplier: C.u8(tsdInfo.Multiplier),
			indirect:   C.u8(tsdInfo.Indirect),
		},

		interpreter_curcop:       C.u16(vms.interpreter.curcop),
		interpreter_curstackinfo: C.u16(vms.interpreter.curstackinfo),

		si_cxstack: C.u8(vms.stackinfo.si_cxstack),
		si_next:    C.u8(vms.stackinfo.si_next),
		si_cxix:    C.u8(vms.stackinfo.si_cxix),
		si_type:    C.u8(vms.stackinfo.si_type),

		context_type:          C.u8(vms.context.cx_type),
		context_blk_oldcop:    C.u8(vms.context.blk_oldcop),
		context_blk_sub_retop: C.u8(vms.context.blk_sub_retop),
		context_blk_sub_cv:    C.u8(vms.context.blk_sub_cv),
		context_sizeof:        C.u8(vms.context.sizeof),

		sv_flags:  C.u8(vms.sv.sv_flags),
		sv_any:    C.u8(vms.sv.sv_any),
		svu_gp:    C.u8(vms.sv.svu_gp),
		xcv_flags: C.u8(vms.xpvcv.xcv_flags),
		xcv_gv:    C.u8(vms.xpvcv.xcv_gv),
		gp_egv:    C.u8(vms.gp.gp_egv),
	}

	err := ebpf.UpdateProcData(libpf.Perl, pid, unsafe.Pointer(&data))
	if err != nil {
		return err
	}

	i.procInfoInserted = true
	return nil
}

func (i *perlInstance) Detach(ebpf interpreter.EbpfHandler, pid util.PID) error {
	if !i.procInfoInserted {
		return nil
	}
	return ebpf.DeleteProcData(libpf.Perl, pid)
}

func (i *perlInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToHEKStats := i.addrToHEK.ResetMetrics()
	addrToCOPStats := i.addrToCOP.ResetMetrics()
	addrToGVStats := i.addrToGV.ResetMetrics()

	return []metrics.Metric{
		{
			ID:    metrics.IDPerlSymbolizationSuccess,
			Value: metrics.MetricValue(i.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDPerlSymbolizationFailure,
			Value: metrics.MetricValue(i.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDPerlAddrToHEKHit,
			Value: metrics.MetricValue(addrToHEKStats.Hits),
		},
		{
			ID:    metrics.IDPerlAddrToHEKMiss,
			Value: metrics.MetricValue(addrToHEKStats.Misses),
		},
		{
			ID:    metrics.IDPerlAddrToHEKAdd,
			Value: metrics.MetricValue(addrToHEKStats.Inserts),
		},
		{
			ID:    metrics.IDPerlAddrToHEKDel,
			Value: metrics.MetricValue(addrToHEKStats.Removals),
		},
		{
			ID:    metrics.IDPerlAddrToCOPHit,
			Value: metrics.MetricValue(addrToCOPStats.Hits),
		},
		{
			ID:    metrics.IDPerlAddrToCOPMiss,
			Value: metrics.MetricValue(addrToCOPStats.Misses),
		},
		{
			ID:    metrics.IDPerlAddrToCOPAdd,
			Value: metrics.MetricValue(addrToCOPStats.Inserts),
		},
		{
			ID:    metrics.IDPerlAddrToCOPDel,
			Value: metrics.MetricValue(addrToCOPStats.Removals),
		},
		{
			ID:    metrics.IDPerlAddrToGVHit,
			Value: metrics.MetricValue(addrToGVStats.Hits),
		},
		{
			ID:    metrics.IDPerlAddrToGVMiss,
			Value: metrics.MetricValue(addrToGVStats.Misses),
		},
		{
			ID:    metrics.IDPerlAddrToGVAdd,
			Value: metrics.MetricValue(addrToGVStats.Inserts),
		},
		{
			ID:    metrics.IDPerlAddrToGVDel,
			Value: metrics.MetricValue(addrToGVStats.Removals),
		},
		{
			ID:    metrics.IDPerlHekLen,
			Value: metrics.MetricValue(i.hekLen.Swap(0)),
		},
	}, nil
}

func (i *perlInstance) getHEK(addr libpf.Address) (string, error) {
	if addr == 0 {
		return "", errors.New("null hek pointer")
	}
	if value, ok := i.addrToHEK.Get(addr); ok {
		return value, nil
	}
	vms := &i.d.vmStructs

	// Read the Hash Element Key (HEK) length and readahead bytes in
	// attempt to avoid second system call to read the target string.
	// 128 is chosen arbitrarily as "hopefully good enough"; this value can
	// be increased if it turns out to be necessary.
	var buf [128]byte
	if err := i.rm.Read(addr, buf[:]); err != nil {
		return "", err
	}
	hekLen := npsr.Uint32(buf[:], vms.hek.hek_len)

	// For our better understanding and future improvement we track the maximum value we get for
	// hekLen and report it.
	util.AtomicUpdateMaxUint32(&i.hekLen, hekLen)

	if hekLen > hekLenLimit {
		return "", fmt.Errorf("hek too large (%d)", hekLen)
	}

	syncPoolData := i.memPool.Get().(*[]byte)
	if syncPoolData == nil {
		return "", errors.New("failed to get memory from sync pool")
	}

	defer func() {
		// Reset memory and return it for reuse.
		for j := uint32(0); j < hekLen; j++ {
			(*syncPoolData)[j] = 0x0
		}
		i.memPool.Put(syncPoolData)
	}()

	tmp := (*syncPoolData)[:hekLen]
	// Always allocate the string separately so it does not hold the backing
	// buffer that might be larger than needed
	numCopied := copy(tmp, buf[vms.hek.hek_key:])
	if hekLen > uint32(numCopied) {
		err := i.rm.Read(addr+libpf.Address(vms.hek.hek_key+uint(numCopied)), tmp[numCopied:])
		if err != nil {
			return "", err
		}
	}
	s := string(tmp)
	if !util.IsValidString(s) {
		log.Debugf("Extracted invalid hek string at 0x%x '%v'", addr, []byte(s))
		return "", fmt.Errorf("extracted invalid hek string at 0x%x", addr)
	}
	i.addrToHEK.Add(addr, s)

	return s, nil
}

func (i *perlInstance) getHVName(hvAddr libpf.Address) (string, error) {
	if hvAddr == 0 {
		return "", nil
	}
	vms := &i.d.vmStructs
	hv := make([]byte, vms.sv.sizeof)
	if err := i.rm.Read(hvAddr, hv); err != nil {
		return "", err
	}
	hvFlags := npsr.Uint32(hv, vms.sv.sv_flags)
	if hvFlags&SVt_MASK != SVt_PVHV {
		return "", errors.New("not a HV")
	}

	xpvhvAddr := npsr.Ptr(hv, vms.sv.sv_any)
	end := i.rm.Uint64(xpvhvAddr + libpf.Address(vms.xpvhv.xhv_max))

	xpvhvAux := make([]byte, vms.xpvhv_aux.sizeof)
	if i.d.version < perlVersion(5, 35, 0) {
		// The aux structure is at the end of the array. Calculate its address.
		arrayAddr := npsr.Ptr(hv, vms.sv.svu_hash)
		xpvhvAuxAddr := arrayAddr + libpf.Address((end+1)*8)
		if err := i.rm.Read(xpvhvAuxAddr, xpvhvAux); err != nil {
			return "", err
		}
	} else {
		// In Perl 5.36.x.XPVHV got replaced with xpvhv_with_aux to hold this information.
		// https://github.com/Perl/perl5/commit/94ee6ed79dbca73d0345b745534477e4017fb990
		if err := i.rm.Read(xpvhvAddr+libpf.Address(vms.xpvhv_with_aux.xpvhv_aux),
			xpvhvAux); err != nil {
			return "", err
		}
	}

	nameCount := npsr.Int32(xpvhvAux, vms.xpvhv_aux.xhv_name_count)
	hekAddr := npsr.Ptr(xpvhvAux, vms.xpvhv_aux.xhv_name_u)
	// A non-zero name count here implies that the
	// GV belongs to a symbol table that has been
	// altered in some way (Perl calls this a Stash, see
	// https://www.perlmonks.org/?node=perlguts#Stashes_and_Globs for more).
	//
	// Stashes can be manipulated directly from Perl code, but it
	// can also happen during normal operation and it messes with the layout of HVs.
	// The exact link for this behavior is here:
	// https://github.com/Perl/perl5/blob/v5.32.0/hv.h#L114
	if nameCount > 0 {
		// When xhv_name_count > 0, it points to a HEK** array and the
		// first element is the name.
		hekAddr = i.rm.Ptr(hekAddr)
	} else if nameCount < 0 {
		// When xhv_name_count < 0, it points to a HEK** array and the
		// second element is the name.
		hekAddr = i.rm.Ptr(hekAddr + libpf.Address(vms.xpvhv_aux.pointer_size))
	}

	return i.getHEK(hekAddr)
}

func (i *perlInstance) getGV(gvAddr libpf.Address, nameOnly bool) (string, error) {
	if gvAddr == 0 {
		return "", nil
	}
	if value, ok := i.addrToGV.Get(gvAddr); ok {
		return value, nil
	}

	vms := &i.d.vmStructs

	// Follow the GV's "body" pointer to get the function name
	xpvgvAddr := i.rm.Ptr(gvAddr + libpf.Address(vms.sv.sv_any))
	hekAddr := i.rm.Ptr(xpvgvAddr + libpf.Address(vms.xpvgv.xivu_namehek))
	gvName, err := i.getHEK(hekAddr)
	if err != nil {
		return "", err
	}

	if !nameOnly && gvName != "" {
		stashAddr := i.rm.Ptr(xpvgvAddr + libpf.Address(vms.xpvgv.xgv_stash))
		packageName, err := i.getHVName(stashAddr)
		if err != nil {
			return "", err
		}

		// Build the qualified name
		if packageName == "" {
			// per Perl_gv_fullname4
			packageName = "__ANON__"
		}
		gvName = packageName + "::" + gvName
	}

	i.addrToGV.Add(gvAddr, gvName)

	return gvName, nil
}

// getCOP reads and caches a Control OP from remote interpreter. On success, the COP
// and a bool if it was cached, is returned. On error, the error.
func (i *perlInstance) getCOP(copAddr libpf.Address, funcName string) (*perlCOP, bool, error) {
	key := copKey{
		copAddr:  copAddr,
		funcName: funcName,
	}
	if value, ok := i.addrToCOP.Get(key); ok {
		return value, true, nil
	}

	vms := &i.d.vmStructs
	cop := make([]byte, vms.cop.sizeof)
	if err := i.rm.Read(copAddr, cop); err != nil {
		return nil, false, err
	}

	sourceFileName := interpreter.UnknownSourceFile
	if i.d.stateInTSD {
		// cop_file is a pointer to nul terminated string
		sourceFileAddr := npsr.Ptr(cop, vms.cop.cop_file)
		sourceFileName = i.rm.String(sourceFileAddr)
	} else {
		// cop_file is a pointer to GV
		sourceFileGVAddr := npsr.Ptr(cop, vms.cop.cop_file)
		var err error
		sourceFileName, err = i.getGV(sourceFileGVAddr, true)
		if err == nil && len(sourceFileName) <= 2 {
			err = fmt.Errorf("sourcefile gv length too small (%d)", len(sourceFileName))
		}
		if err != nil {
			return nil, false, err
		}
		sourceFileName = sourceFileName[2:]
	}
	if !util.IsValidString(sourceFileName) {
		log.Debugf("Extracted invalid source file name '%v'", []byte(sourceFileName))
		return nil, false, errors.New("extracted invalid source file name")
	}

	line := npsr.Uint32(cop, vms.cop.cop_line)

	// Synthesize a FileID.
	// The fnv hash Write() method calls cannot fail, so it's safe to ignore the errors.
	h := fnv.New128a()
	_, _ = h.Write([]byte{uint8(libpf.PerlFrame)})
	_, _ = h.Write([]byte(sourceFileName))
	// Unfortunately there is very little information to extract for each function
	// from the GV. Use just the function name at this time.
	_, _ = h.Write([]byte(funcName))
	fileID, err := libpf.FileIDFromBytes(h.Sum(nil))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create a file ID: %v", err)
	}

	c := &perlCOP{
		sourceFileName: sourceFileName,
		fileID:         fileID,
		line:           libpf.AddressOrLineno(line),
	}
	i.addrToCOP.Add(key, c)
	return c, false, nil
}

func (i *perlInstance) Symbolize(symbolReporter reporter.SymbolReporter,
	frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.Perl) {
		return interpreter.ErrMismatchInterpreterType
	}

	sfCounter := successfailurecounter.New(&i.successCount, &i.failCount)
	defer sfCounter.DefaultToFailure()

	gvAddr := libpf.Address(frame.File)
	functionName, err := i.getGV(gvAddr, false)
	if err != nil {
		return fmt.Errorf("failed to get Perl GV %x: %v", gvAddr, err)
	}

	// This can only happen if gvAddr is 0,
	// which we use to denote code at the top level (e.g
	// code in the file not inside a function).
	if functionName == "" {
		functionName = interpreter.TopLevelFunctionName
	}
	copAddr := libpf.Address(frame.Lineno)
	cop, seen, err := i.getCOP(copAddr, functionName)
	if err != nil {
		return fmt.Errorf("failed to get Perl COP %x: %v", copAddr, err)
	}

	lineno := cop.line

	trace.AppendFrame(libpf.PerlFrame, cop.fileID, lineno)

	if !seen {
		symbolReporter.FrameMetadata(
			cop.fileID, lineno, util.SourceLineno(lineno), 0,
			functionName, cop.sourceFileName)

		log.Debugf("[%d] [%x] %v at %v:%v",
			len(trace.FrameTypes),
			cop.fileID, functionName,
			cop.sourceFileName, lineno)
	}

	sfCounter.ReportSuccess()
	return nil
}
