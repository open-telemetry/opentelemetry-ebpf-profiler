/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package perl

// Perl interpreter unwinder

// Start by reading the 'perlguts illustrated' it is really helpful on explaining
// the Perl VM internal implementation:
//   https://github.com/rurban/illguts/blob/master/illguts.pdf
//
// Additional recommended reading from the Perl manuals:
//   https://perldoc.perl.org/perlguts#Dynamic-Scope-and-the-Context-Stack
//   https://perldoc.perl.org/perlinterp#OP-TREES
//   https://perldoc.perl.org/perlcall
//   https://perldoc.perl.org/perlxs

// It is said that reading Perl code makes your eyes bleed.
// I say reading Perl interpreter code with all the unsafe casting,
// and unions makes your brains bleed. -tt

// Perl uses a SV (Scalar Value) as the base "variant" type for all Perl VM
// variables. It can be a one of various different types, but we are mostly
// interested about CV (Code Value), GV (Glob Value, aka. symbol name), and
// HV (Hash Value). Typically the only difference between e.g. SV and CV is
// only that the pointer is of different types, and casts between these structs
// are done if the type code shows the cast is ok.
//
// Much of the extra data is behind the "any" or "variant" pointer. Typically
// named XPVxV (where 'x' changes, so XPVCV for CV). Other types may have another
// additional pointer in the base 'SV' too, like the HV and GV. Bulk of the code
// is just following these pointers (ensuring right types). Please refer to the
// Perlguts illustrated for the relationships.
//
// See the perl_tracer.ebpf.c for more detailed unwinding explanation.
// The tracer will send the 'EGV' (effective GV, aka canonical symbol name) and
// the 'COP' for each frame. This code will stringify the EGV to a full qualified
// symbol name, and extract the source file/line from the COP. The EGV is null for
// the bottom frame which is the global file scope (not inside a function).
//
// Unfortunately, it is not possible to extract file/line where some function is
// defined. The observant may note that the 'struct gp' which is the symbol definition
// holds source file name and line number of its "first definition". But this refers
// either to the closing '}' of the sub definition, or the line of the object
// reference creation ... both of which are not useful for us. It really seems to
// not be possible to get a function's start line.

import (
	"debug/elf"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cespare/xxhash/v2"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/freelru"
	npsr "github.com/elastic/otel-profiling-agent/libpf/nopanicslicereader"
	"github.com/elastic/otel-profiling-agent/libpf/remotememory"
	"github.com/elastic/otel-profiling-agent/libpf/successfailurecounter"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/support"
	"github.com/elastic/otel-profiling-agent/tpbase"

	log "github.com/sirupsen/logrus"
)

// #include "../../support/ebpf/types.h"
import "C"

// nolint:golint,stylecheck,revive
const (
	// Scalar Value types (SVt)
	// https://github.com/Perl/perl5/blob/v5.32.0/sv.h#L132-L166
	SVt_MASK uint32 = 0x1f
	SVt_PVHV uint32 = 12

	// Arbitrary string length limit to make sure we don't panic with out-of-memory
	hekLenLimit = 0x10000
)

var (
	// regex for the interpreter executable
	perlRegex    = regexp.MustCompile(`^(?:.*/)?perl$`)
	libperlRegex = regexp.MustCompile(`^(?:.*/)?libperl\.so[^/]*$`)

	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &perlData{}
	_ interpreter.Instance = &perlInstance{}
)

type perlData struct {
	// vmStructs reflects the Perl internal class names and the offsets of named field
	// The struct names are based on the Perl C "struct name", the alternate typedef seen
	// mostly in code is in parenthesis.
	// nolint:golint,stylecheck,revive
	vmStructs struct {
		// interpreter struct (PerlInterpreter) is defined in intrpvar.h via macro trickery
		// https://github.com/Perl/perl5/blob/v5.32.0/intrpvar.h
		interpreter struct {
			curcop       uint
			curstackinfo uint
		}
		// stackinfo struct (PERL_SI) is defined in cop.h
		// https://github.com/Perl/perl5/blob/v5.32.0/cop.h#L1037-L1055
		stackinfo struct {
			si_cxstack uint
			si_next    uint
			si_cxix    uint
			si_type    uint
		}
		// context struct (PERL_CONTEXT) is defined in cop.h
		// https://github.com/Perl/perl5/blob/v5.32.0/cop.h#L878-L884
		context struct {
			cx_type       uint
			blk_oldcop    uint
			blk_sub_retop uint
			blk_sub_cv    uint
			sizeof        uint
		}
		// cop struct (COP), a "control op" is defined in cop.h
		// https://github.com/Perl/perl5/blob/v5.32.0/cop.h#L397-L424
		cop struct {
			cop_line uint
			cop_file uint
			sizeof   uint
		}
		// sv struct (SV) is "Scalar Value", the generic "base" for all
		// perl variants, and is horrendously cast to other types as needed.
		// https://github.com/Perl/perl5/blob/v5.32.0/sv.h#L233-L236
		sv struct {
			sv_any   uint
			sv_flags uint
			svu_gp   uint
			svu_hash uint
			sizeof   uint
		}
		// xpvcv struct (XPVCV) is "Code Value object" (the data PV points to)
		// https://github.com/Perl/perl5/blob/v5.32.0/cv.h#L13-L16
		xpvcv struct {
			xcv_flags uint
			xcv_gv    uint
		}
		// xpvgv struct (XPVGV) is "Glob Value object" (the data GV points to)
		// https://github.com/Perl/perl5/blob/v5.32.0/sv.h#L571-L575
		xpvgv struct {
			xivu_namehek uint
			xgv_stash    uint
		}
		// xpvhv struct (XPVHV) is a "Hash Value" (that is the Hash struct)
		// https://github.com/Perl/perl5/blob/v5.32.0/hv.h#L135-L140
		xpvhv struct {
			xhv_max uint
		}
		// xpvhv_with_aux is the successor of XPVHV starting in Perl 5.36.
		// https://github.com/Perl/perl5/blob/v5.36.0/hv.h#L149-L155
		xpvhv_with_aux struct {
			xpvhv_aux uint
		}
		// xpvhv_aux struct is the Hash ancillary data structure
		// https://github.com/Perl/perl5/blob/v5.32.0/hv.h#L108-L128
		xpvhv_aux struct {
			xhv_name_u     uint
			xhv_name_count uint
			sizeof         uint
			pointer_size   uint
		}
		// gp struct (GP) is apparently "Glob Private", essentially a function definition
		// https://github.com/Perl/perl5/blob/v5.32.0/gv.h#L11-L24
		gp struct {
			gp_egv uint
		}
		// hek struct (HEK) is "Hash Entry Key", a hash/len/key triplet
		// https://github.com/Perl/perl5/blob/v5.32.0/hv.h#L44-L57
		hek struct {
			hek_len uint
			hek_key uint
		}
	}

	// stateAddr is the address of the Perl state address (TSD or global)
	stateAddr libpf.SymbolValue

	// version contains the Perl version
	version uint32

	// stateInTSD is set if the we have state TSD key address
	stateInTSD bool
}

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

func (i *perlInstance) UpdateTSDInfo(ebpf interpreter.EbpfHandler, pid libpf.PID,
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

func (i *perlInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	if !i.procInfoInserted {
		return nil
	}
	return ebpf.DeleteProcData(libpf.Perl, pid)
}

func (i *perlInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	addrToHEKStats := i.addrToHEK.GetAndResetStatistics()
	addrToCOPStats := i.addrToCOP.GetAndResetStatistics()
	addrToGVStats := i.addrToGV.GetAndResetStatistics()

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
			Value: metrics.MetricValue(addrToHEKStats.Hit),
		},
		{
			ID:    metrics.IDPerlAddrToHEKMiss,
			Value: metrics.MetricValue(addrToHEKStats.Miss),
		},
		{
			ID:    metrics.IDPerlAddrToHEKAdd,
			Value: metrics.MetricValue(addrToHEKStats.Added),
		},
		{
			ID:    metrics.IDPerlAddrToHEKDel,
			Value: metrics.MetricValue(addrToHEKStats.Deleted),
		},
		{
			ID:    metrics.IDPerlAddrToCOPHit,
			Value: metrics.MetricValue(addrToCOPStats.Hit),
		},
		{
			ID:    metrics.IDPerlAddrToCOPMiss,
			Value: metrics.MetricValue(addrToCOPStats.Miss),
		},
		{
			ID:    metrics.IDPerlAddrToCOPAdd,
			Value: metrics.MetricValue(addrToCOPStats.Added),
		},
		{
			ID:    metrics.IDPerlAddrToCOPDel,
			Value: metrics.MetricValue(addrToCOPStats.Deleted),
		},
		{
			ID:    metrics.IDPerlAddrToGVHit,
			Value: metrics.MetricValue(addrToGVStats.Hit),
		},
		{
			ID:    metrics.IDPerlAddrToGVMiss,
			Value: metrics.MetricValue(addrToGVStats.Miss),
		},
		{
			ID:    metrics.IDPerlAddrToGVAdd,
			Value: metrics.MetricValue(addrToGVStats.Added),
		},
		{
			ID:    metrics.IDPerlAddrToGVDel,
			Value: metrics.MetricValue(addrToGVStats.Deleted),
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
	libpf.AtomicUpdateMaxUint32(&i.hekLen, hekLen)

	if hekLen > hekLenLimit {
		return "", fmt.Errorf("hek too large (%d)", hekLen)
	}

	syncPoolData := i.memPool.Get().(*[]byte)
	if syncPoolData == nil {
		return "", fmt.Errorf("failed to get memory from sync pool")
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
	if !libpf.IsValidString(s) {
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
	max := i.rm.Uint64(xpvhvAddr + libpf.Address(vms.xpvhv.xhv_max))

	xpvhvAux := make([]byte, vms.xpvhv_aux.sizeof)
	if i.d.version < 0x052300 {
		// The aux structure is at the end of the array. Calculate its address.
		arrayAddr := npsr.Ptr(hv, vms.sv.svu_hash)
		xpvhvAuxAddr := arrayAddr + libpf.Address((max+1)*8)
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
	if !libpf.IsValidString(sourceFileName) {
		log.Debugf("Extracted invalid source file name '%v'", []byte(sourceFileName))
		return nil, false, fmt.Errorf("extracted invalid source file name")
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
			cop.fileID, lineno, libpf.SourceLineno(lineno), 0,
			functionName, cop.sourceFileName)

		log.Debugf("[%d] [%x] %v at %v:%v",
			len(trace.FrameTypes),
			cop.fileID, functionName,
			cop.sourceFileName, lineno)
	}

	sfCounter.ReportSuccess()
	return nil
}

func (d *perlData) String() string {
	ver := d.version
	return fmt.Sprintf("Perl %d.%d.%d", (ver>>16)&0xff, (ver>>8)&0xff, ver&0xff)
}

func (d *perlData) Attach(_ interpreter.EbpfHandler, _ libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	addrToHEK, err := freelru.New[libpf.Address, string](interpreter.LruFunctionCacheSize,
		libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	addrToCOP, err := freelru.New[copKey, *perlCOP](interpreter.LruFunctionCacheSize*8,
		hashCOPKey)
	if err != nil {
		return nil, err
	}

	addrToGV, err := freelru.New[libpf.Address, string](interpreter.LruFunctionCacheSize,
		libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	return &perlInstance{
		d:         d,
		rm:        rm,
		bias:      C.u64(bias),
		addrToHEK: addrToHEK,
		addrToCOP: addrToCOP,
		addrToGV:  addrToGV,
		memPool: sync.Pool{
			New: func() any {
				// To avoid resizing of the returned byte slize we size new
				// allocations to hekLenLimit.
				buf := make([]byte, hekLenLimit)
				return &buf
			},
		},
	}, nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	mainDSO := false
	if !libperlRegex.MatchString(info.FileName()) {
		mainDSO = true
		if !perlRegex.MatchString(info.FileName()) {
			return nil, nil
		}
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	if mainDSO {
		var needed []string
		needed, err = ef.DynString(elf.DT_NEEDED)
		if err != nil {
			return nil, err
		}
		for _, n := range needed {
			if libperlRegex.MatchString(n) {
				// 'perl' linked with 'libperl'. The beef is in the library,
				// so do not try to inspect the shim main binary.
				return nil, nil
			}
		}
	}

	// The version is encoded in these globals since Perl 5.15.0.
	// https://github.com/Perl/perl5/blob/v5.32.0/perl.h#L4745-L4754
	var verBytes [3]byte
	for i, sym := range []libpf.SymbolName{"PL_revision", "PL_version", "PL_subversion"} {
		var addr libpf.SymbolValue
		addr, err = ef.LookupSymbolAddress(sym)
		if err == nil {
			_, err = ef.ReadVirtualMemory(verBytes[i:i+1], int64(addr))
		}
		if err != nil {
			return nil, fmt.Errorf("perl symbol '%s': %v", sym, err)
		}
	}

	version := uint32(verBytes[0])*0x10000 + uint32(verBytes[1])*0x100 + uint32(verBytes[2])
	log.Debugf("Perl version %v.%v.%v", verBytes[0], verBytes[1], verBytes[2])

	// Currently tested and supported 5.28.x - 5.36.x.
	// Could possibly support older Perl versions somewhere back to 5.14-5.20, by just
	// checking the introspection offset validity. 5.14 had major rework for internals.
	// And 5.18 had some HV related changes.
	const minVer, maxVer = 0x051c00, 0x052500
	if version < minVer || version >= maxVer {
		return nil, fmt.Errorf("unsupported Perl %d.%d.%d (need >= %d.%d and < %d.%d)",
			verBytes[0], verBytes[1], verBytes[2],
			(minVer>>16)&0xff, (minVer>>8)&0xff,
			(maxVer>>16)&0xff, (maxVer>>8)&0xff)
	}

	// "PL_thr_key" contains the TSD key since Perl 5.15.2
	// https://github.com/Perl/perl5/blob/v5.32.0/perlvars.h#L45
	stateInTSD := true
	var curcopAddr, cursiAddr libpf.SymbolValue
	stateAddr, err := ef.LookupSymbolAddress("PL_thr_key")
	if err != nil {
		// If Perl is built without threading support, this symbol is not found.
		// Fallback to using the global interpreter state.
		curcopAddr, err = ef.LookupSymbolAddress("PL_curcop")
		if err != nil {
			return nil, fmt.Errorf("perl %x: PL_curcop not found: %v", version, err)
		}
		cursiAddr, err = ef.LookupSymbolAddress("PL_curstackinfo")
		if err != nil {
			return nil, fmt.Errorf("perl %x: PL_curstackinfo not found: %v", version, err)
		}
		stateInTSD = false
		if curcopAddr < cursiAddr {
			stateAddr = curcopAddr
		} else {
			stateAddr = cursiAddr
		}
	}

	// Perl_runops_standard is the main loop since Perl 5.6.0 (1999)
	// https://github.com/Perl/perl5/blob/v5.32.0/run.c#L37
	// Also Perl_runops_debug exists which is used when the perl debugger is
	// active, but this is not supported currently.
	interpRanges, err := info.GetSymbolAsRanges("Perl_runops_standard")
	if err != nil {
		return nil, err
	}

	d := &perlData{
		version:    version,
		stateAddr:  stateAddr,
		stateInTSD: stateInTSD,
	}

	// Perl does not provide introspection data, hard code the struct field
	// offsets based on detected version. Some values can be fairly easily
	// calculated from the struct definitions, but some are looked up by
	// using gdb and getting the field offset directly from debug data.
	vms := &d.vmStructs
	if stateInTSD {
		if version >= 0x052200 {
			// For Perl 5.34 PerlInterpreter changed and so did its offsets.
			vms.interpreter.curcop = 0xd0
			vms.interpreter.curstackinfo = 0xe0
		} else {
			vms.interpreter.curcop = 0xe0
			vms.interpreter.curstackinfo = 0xf0
		}
	} else {
		vms.interpreter.curcop = uint(curcopAddr - stateAddr)
		vms.interpreter.curstackinfo = uint(cursiAddr - stateAddr)
	}
	vms.stackinfo.si_cxstack = 0x08
	vms.stackinfo.si_next = 0x18
	vms.stackinfo.si_cxix = 0x20
	vms.stackinfo.si_type = 0x28
	vms.context.cx_type = 0
	vms.context.blk_oldcop = 0x10
	vms.context.blk_sub_retop = 0x30
	vms.context.blk_sub_cv = 0x40
	vms.context.sizeof = 0x60
	vms.cop.cop_line = 0x24
	vms.cop.cop_file = 0x30
	vms.cop.sizeof = 0x50
	vms.sv.sv_any = 0x0
	vms.sv.sv_flags = 0xc
	vms.sv.svu_gp = 0x10
	vms.sv.svu_hash = 0x10
	vms.sv.sizeof = 0x18
	vms.xpvcv.xcv_flags = 0x5c
	vms.xpvcv.xcv_gv = 0x38
	vms.xpvgv.xivu_namehek = 0x20
	vms.xpvgv.xgv_stash = 0x28
	vms.xpvhv.xhv_max = 0x18
	vms.xpvhv_aux.xhv_name_u = 0x0
	vms.xpvhv_aux.xhv_name_count = 0x1c
	vms.xpvhv_aux.sizeof = 0x38
	vms.xpvhv_aux.pointer_size = 8
	vms.gp.gp_egv = 0x38
	vms.hek.hek_len = 4
	vms.hek.hek_key = 8

	if version >= 0x052000 {
		vms.stackinfo.si_type = 0x2c
		vms.context.blk_sub_cv = 0x48
		vms.context.sizeof = 0x68
		vms.cop.sizeof = 0x58
	}

	if version >= 0x052300 {
		vms.xpvhv_aux.xhv_name_count = 0x3c
		vms.xpvhv_with_aux.xpvhv_aux = 0x20
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindPerl,
		info.FileID(), interpRanges); err != nil {
		return nil, err
	}

	return d, nil
}
