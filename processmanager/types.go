/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package processmanager

import (
	"sync"
	"sync/atomic"

	lru "github.com/elastic/go-freelru"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/metrics"
	pmebpf "github.com/elastic/otel-profiling-agent/processmanager/ebpf"
	eim "github.com/elastic/otel-profiling-agent/processmanager/execinfomanager"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/tpbase"
)

// elfInfo contains cached data from an executable needed for processing mappings.
// A negative cache entry may also be recorded with err set to indicate permanent
// error. This avoids inspection of non-ELF or corrupted files again and again.
type elfInfo struct {
	err           error
	lastModified  int64
	fileID        host.FileID
	addressMapper pfelf.AddressMapper
}

// ProcessManager is responsible for managing the events happening throughout the lifespan of a
// process.
type ProcessManager struct {
	// A mutex to synchronize access to internal data within this struct.
	mu sync.RWMutex

	// interpreterTracerEnabled indicates if at last one non-native tracer is loaded.
	interpreterTracerEnabled bool

	// eim stores per executable (file ID) information.
	eim *eim.ExecutableInfoManager

	// interpreters records the interpreter.Instance interface which contains hooks for
	// process exits, and various other situations needing interpreter specific attention.
	// The key of the first map is a process ID, while the key of the second map is
	// the unique on-disk identifier of the interpreter DSO.
	interpreters map[libpf.PID]map[libpf.OnDiskFileIdentifier]interpreter.Instance

	// pidToProcessInfo keeps track of the executable memory mappings in addressSpace
	// for each pid.
	pidToProcessInfo map[libpf.PID]*processInfo

	// exitEvents records the pid exit time and is a list of pending exit events to be handled.
	exitEvents map[libpf.PID]libpf.KTime

	// ebpf contains the interface to manipulate ebpf maps
	ebpf pmebpf.EbpfHandler

	// FileIDMapper provides a cache that implements the FileIDMapper interface. The tracer writes
	// the 64-bit to 128-bit file ID mapping to the cache, as this is where the two values are
	// created. The attached interpreters read from the cache when converting traces prior to
	// sending to the collection agent. The cache resides in this package instead of the ebpf
	// package to prevent circular imports.
	FileIDMapper FileIDMapper

	// elfInfoCacheHit
	elfInfoCacheHit  atomic.Uint64
	elfInfoCacheMiss atomic.Uint64

	// mappingStats are statistics for parsing process mappings
	mappingStats struct {
		errProcNotExist    atomic.Uint32
		errProcESRCH       atomic.Uint32
		errProcPerm        atomic.Uint32
		numProcAttempts    atomic.Uint32
		maxProcParseUsec   atomic.Uint32
		totalProcParseUsec atomic.Uint32
	}

	// elfInfoCache provides a cache to quickly retrieve the ELF info and fileID for a particular
	// executable. It caches results based on iNode number and device ID. Locked LRU.
	elfInfoCache *lru.LRU[libpf.OnDiskFileIdentifier, elfInfo]

	// reporter is the interface to report symbolization information
	reporter reporter.SymbolReporter

	// Reporting function which is used to report information to our backend.
	metricsAddSlice func([]metrics.Metric)

	// pidPageToMappingInfoSize reflects the current size of the eBPF hash map
	// pid_page_to_mapping_info.
	pidPageToMappingInfoSize uint64

	// filterErrorFrames determines whether error frames are dropped by `ConvertTrace`.
	filterErrorFrames bool
}

// Mapping represents an executable memory mapping of a process.
type Mapping struct {
	// FileID represents the host-wide unique identifier of the mapped file.
	FileID host.FileID

	// Vaddr represents the starting virtual address of the mapping.
	Vaddr libpf.Address

	// Bias is the offset between the ELF on-disk virtual address space and the
	// virtual address where it is actually mapped in the process. Thus it is the
	// virtual address bias or "ASLR offset". It serves as a translation offset
	// from the process VA space into the VA space of the ELF file. It's calculated as
	// `bias = vaddr_in_proc - vaddr_in_elf`.
	// Adding the bias to a VA in ELF space translates it into process space.
	Bias uint64

	// Length represents the memory size of the mapping.
	Length uint64

	// Device number of the backing file
	Device uint64

	// Inode number of the backing file
	Inode uint64

	// File offset of the backing file
	FileOffset uint64
}

// GetOnDiskFileIdentifier returns the OnDiskFileIdentifier for the mapping
func (m *Mapping) GetOnDiskFileIdentifier() libpf.OnDiskFileIdentifier {
	return libpf.OnDiskFileIdentifier{
		DeviceID: m.Device,
		InodeNum: m.Inode,
	}
}

// addressSpace represents the address space of a process. It maps the known start addresses
// of executable mappings to the corresponding mappedFile information.
type addressSpace map[libpf.Address]Mapping

// processInfo contains information about the executable mappings
// and Thread Specific Data of a process.
type processInfo struct {
	// executable mappings
	mappings addressSpace
	// C-library Thread Specific Data information
	tsdInfo *tpbase.TSDInfo
}
