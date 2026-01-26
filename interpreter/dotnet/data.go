// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// globalVar is a helper type to decode a Global definition from CDAC JSON contract
// https://github.com/dotnet/runtime/blob/v10.0.2/docs/design/datacontracts/data_descriptor.md#global-values
type globalVar uint64

func (gv *globalVar) UnmarshalJSON(b []byte) error {
	var fields []string
	err := json.Unmarshal(b, &fields)
	if err != nil {
		return nil
	}
	if len(fields) < 2 {
		return errors.New("unknown global var format")
	}

	switch fields[1] {
	case "uint8", "uint16", "uint32", "uint64":
		var val uint64
		val, err = strconv.ParseUint(fields[0], 0, 64)
		*gv = globalVar(val)
	default:
		err = fmt.Errorf("unexpected global var type: %v", fields[1])
	}
	return err
}

// dotnetCdac reflects the Dotnet JSON contract descriptor data, and contains
// the fields from CDAC that we currently need.
type dotnetCdac struct {
	Types struct {
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/lockedrangelist.h#L12
		lockedRangeList struct {
			SizeOf uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/codeman.h#L612
		RangeSection struct {
			RangeBegin    uint
			RangeEndOpen  uint
			next          uint // old dotnet6/7 (different from NextForDelete in CDAC)
			Flags         uint
			HeapList      uint
			R2RModule     uint
			RangeList     uint
			NextForDelete uint
			SizeOf        uint `json:"!"`
		}
		// https://github.com/dotnet/runtime/blob/v8.0.4/src/coreclr/vm/loaderallocator.hpp#L44
		CodeRangeMapRangeList struct {
			// https://github.com/dotnet/runtime/blob/v8.0.4/src/coreclr/vm/loaderallocator.hpp#L180
			RangeListType uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/codeman.h#L466
		CodeHeapListNode struct {
			Next         uint
			StartAddress uint
			EndAddress   uint
			MapBase      uint
			HeaderMap    uint
			SizeOf       uint `json:"!"`
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/codeman.h#L131-L135
		// NOTE: USE_INDIRECT_CODEHEADER is defined on architectures we care about, and this
		// really reflects the struct _hpRealCodeHdr.
		RealCodeHeader struct {
			DebugInfo  uint
			MethodDesc uint
			SizeOf     uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/method.hpp#L193
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/method.hpp#L1670
		MethodDesc struct {
			Flags3AndTokenRemainder uint
			ChunkIndex              uint
			Flags                   uint
			SizeOf                  uint `json:"!"`
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/method.hpp#L2163
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/method.hpp#L2344
		MethodDescChunk struct {
			MethodTable        uint
			FlagsAndTokenRange uint
			SizeOf             uint `json:"!"`
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/methodtable.h#L518
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/methodtable.h#L3548
		MethodTable struct {
			Module uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/ceeload.h#L601
		Module struct {
			SimpleName uint
			Path       uint // used to calculate the private SimpleName field
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/inc/patchpointinfo.h#L176-L190
		PatchpointInfo struct {
			SizeOf         uint `json:"!"`
			NumberOfLocals uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/stubmgr.h#L204
		StubManager struct {
			SizeOf uint `json:"!"`
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/stubmgr.h#L402
		PrecodeStubManager struct {
			StubPrecodeRangeList  uint
			FixupPrecodeRangeList uint
		}
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/vm/virtualcallstub.h#L721-L768
		VirtualCallStubManager struct {
			Next uint
		}
	}

	Globals struct {
		MethodDescTokenRemainderBitCount globalVar
		MethodDescAlignment              globalVar
	}

	Contracts struct {
		ExecutionManager uint
	}

	// The additional data not present in CDAC that we track or synthesize.

	// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/debug/ee/dactable.cpp#L81
	dacTable struct {
		// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/inc/dacvars.h#L78
		ExecutionManagerCodeRangeList uint
		PrecodeStubManager            uint
		StubLinkStubManager           uint
		ThunkHeapStubManager          uint
		DelegateInvokeStubManager     uint
		VirtualCallStubManagerManager uint
	}

	calculated struct {
		MethodDescChunkTokenRangeMask uint16
		MethodDescTokenRemainderMask  uint16
	}
}

type dotnetData struct {
	// version contains the version
	version uint32

	// dacTableAddr contains the ELF symbol 'g_dacTable' value
	// https://github.com/dotnet/runtime/blob/v7.0.15/src/coreclr/debug/ee/dactable.cpp#L80-L81
	dacTableAddr libpf.SymbolValue

	// cdacDescAddr contains the ELF symbol 'DotNetRuntimeContractDescriptor' value
	// https://github.com/dotnet/runtime/blob/v10.0.2/docs/design/datacontracts/contract-descriptor.md
	cdacDescAddr libpf.SymbolValue

	// method to walk range sections
	walkRangeSectionsMethod func(i *dotnetInstance, ebpf interpreter.EbpfHandler,
		pid libpf.PID) error

	// Once protected dotnetCdac
	xsync.Once[dotnetCdac]
}

func (d *dotnetData) String() string {
	ver := d.version
	return fmt.Sprintf("dotnet %d.%d.%d", (ver>>24)&0xff, (ver>>16)&0xff, ver&0xffff)
}

func (d *dotnetData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	log.Debugf("Attach PID %d, bias %x", pid, bias)

	addrToMethod, err := freelru.New[libpf.Address, *dotnetMethod](interpreter.LruFunctionCacheSize,
		libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	procInfo := support.DotnetProcInfo{
		Version: d.version,
	}
	if err = ebpf.UpdateProcData(libpf.Dotnet, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &dotnetInstance{
		d:              d,
		rm:             rm,
		bias:           bias,
		ranges:         make(map[libpf.Address]dotnetRangeSection),
		moduleToPEInfo: make(map[libpf.Address]*peInfo),
		addrToMethod:   addrToMethod,
	}, nil
}

func (d *dotnetData) Unload(_ interpreter.EbpfHandler) {
}

func (d *dotnetData) newVMData(rm remotememory.RemoteMemory, bias libpf.Address) (dotnetCdac, error) {
	cdac := dotnetCdac{}
	vms := &cdac.Types

	// Addresses
	cdac.Contracts.ExecutionManager = 1
	cdac.dacTable.ExecutionManagerCodeRangeList = 0x0
	vms.RealCodeHeader.DebugInfo = 0x0
	vms.StubManager.SizeOf = 0x10

	// Introspection data present in CDAC starting dotnet 10
	if d.version < dotnetVer(10, 0, 0) {
		// Slot numbers
		cdac.dacTable.StubLinkStubManager = 0xa
		cdac.dacTable.ThunkHeapStubManager = 0xb

		vms.RangeSection.RangeBegin = 0x0
		vms.RangeSection.RangeEndOpen = 0x8

		vms.CodeHeapListNode.Next = 0x0
		vms.CodeHeapListNode.StartAddress = 0x10
		vms.CodeHeapListNode.EndAddress = 0x18
		vms.CodeHeapListNode.MapBase = 0x20
		vms.CodeHeapListNode.HeaderMap = 0x28
		vms.CodeHeapListNode.SizeOf = 0x30

		vms.RealCodeHeader.MethodDesc = 0x18 // NOTE: 0x20 if FEATURE_GDBJIT

		// NOTE: MethodDesc layout is quite different if _DEBUG build
		cdac.Globals.MethodDescAlignment = 0x8
		vms.MethodDesc.Flags3AndTokenRemainder = 0x0
		vms.MethodDesc.ChunkIndex = 0x2
		vms.MethodDesc.Flags = 0x6
		vms.MethodDesc.SizeOf = 0x8

		vms.MethodDescChunk.MethodTable = 0
		vms.MethodDescChunk.FlagsAndTokenRange = 0x12
		vms.MethodDescChunk.SizeOf = 0x18

		vms.MethodTable.Module = 0x18 // NOTE: 0x20 if _DEBUG build
	}

	// Version specific introspection data
	switch d.version >> 24 {
	case 6, 7:
		cdac.dacTable.DelegateInvokeStubManager = 0xe
		vms.RangeSection.next = 0x18
		vms.RangeSection.Flags = 0x28
		vms.RangeSection.HeapList = 0x30
		vms.RangeSection.R2RModule = 0x30
		vms.RangeSection.SizeOf = 0x38
		d.walkRangeSectionsMethod = (*dotnetInstance).walkRangeSectionList
	case 8, 9:
		cdac.Globals.MethodDescTokenRemainderBitCount = 12
		vms.RangeSection.Flags = 0x10
		vms.RangeSection.R2RModule = 0x20
		vms.RangeSection.HeapList = 0x28
		vms.RangeSection.RangeList = 0x30
		vms.RangeSection.SizeOf = 0x38
		vms.Module.SimpleName = 0x108
		fallthrough
	case 10:
		vms.CodeRangeMapRangeList.RangeListType = 0x120
		vms.PatchpointInfo.SizeOf = 32
		vms.PatchpointInfo.NumberOfLocals = 8
		d.walkRangeSectionsMethod = (*dotnetInstance).walkRangeSectionMap
	}

	switch d.version >> 24 {
	case 6:
		cdac.Globals.MethodDescTokenRemainderBitCount = 14
		vms.Module.SimpleName = 0x8
		vms.PatchpointInfo.SizeOf = 20
		vms.PatchpointInfo.NumberOfLocals = 0
	case 7:
		cdac.Globals.MethodDescTokenRemainderBitCount = 13
		// Module inherits from ModuleBase with quite a bit of data
		// see: https://github.com/dotnet/runtime/pull/71271
		vms.Module.SimpleName = 0x100
		// PatchpointInfo was adjusted in:
		// https://github.com/dotnet/runtime/pull/65196
		// https://github.com/dotnet/runtime/pull/61712
		vms.PatchpointInfo.SizeOf = 32
		vms.PatchpointInfo.NumberOfLocals = 8
		// PrecodeStubManager is useful in dotnet7 only
		cdac.dacTable.PrecodeStubManager = 0x9
		vms.lockedRangeList.SizeOf = 0x120
		vms.PrecodeStubManager.StubPrecodeRangeList = vms.StubManager.SizeOf
		vms.PrecodeStubManager.FixupPrecodeRangeList = vms.StubManager.SizeOf +
			vms.lockedRangeList.SizeOf
		cdac.dacTable.VirtualCallStubManagerManager = 0xf
		vms.VirtualCallStubManager.Next = 0x6e8
	case 8:
		cdac.dacTable.VirtualCallStubManagerManager = 0xe
		vms.VirtualCallStubManager.Next = 0x268
	case 10:
		cdac.dacTable.StubLinkStubManager = 0xa
	}

	var err error
	if d.cdacDescAddr != libpf.SymbolValueInvalid {
		// https://github.com/dotnet/runtime/blob/v10.0.2/docs/design/datacontracts/contract-descriptor.md
		hdr := struct {
			magic     uint64
			flags     uint32
			descrSize uint32
			descrPtr  uint64
			dataCount uint32
			pad0      uint32
			dataPtr   uint64
		}{}
		if err = rm.Read(libpf.Address(d.cdacDescAddr)+bias, pfunsafe.FromPointer(&hdr)); err == nil {
			if hdr.magic == 0x0043414443434e44 && hdr.descrSize < 64*1024 {
				jsonData := make([]byte, hdr.descrSize)
				err = rm.Read(libpf.Address(hdr.descrPtr), jsonData)
				if err == nil {
					err = json.Unmarshal(jsonData, &cdac)
					log.Debugf("CDAC data unmarshalled: %v", err)
				}
			}
			// Synthesize missing data
			if vms.Module.SimpleName == 0 {
				vms.Module.SimpleName = vms.Module.Path - 8
			}
			if vms.CodeHeapListNode.SizeOf == 0 {
				vms.CodeHeapListNode.SizeOf = vms.CodeHeapListNode.HeaderMap + 8
			}
			if vms.RangeSection.RangeList == 0 {
				vms.RangeSection.RangeList = vms.RangeSection.HeapList + 8
			}
			if vms.RangeSection.SizeOf == 0 {
				vms.RangeSection.SizeOf = vms.RangeSection.NextForDelete
			}
		}
	}
	vms.RealCodeHeader.SizeOf = vms.RealCodeHeader.MethodDesc + 8

	// Calculated masks
	cdac.calculated.MethodDescTokenRemainderMask = (1 << cdac.Globals.MethodDescTokenRemainderBitCount) - 1
	cdac.calculated.MethodDescChunkTokenRangeMask = (1 << (24 - cdac.Globals.MethodDescTokenRemainderBitCount)) - 1

	return cdac, err
}
