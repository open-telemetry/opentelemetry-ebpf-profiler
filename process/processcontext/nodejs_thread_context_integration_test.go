//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext_test

import (
	"encoding/binary"
	"os"
	"slices"
	"testing"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Pages of a nodeArena, one per object on the walk so a test can make any one
// of them unreadable.
const (
	pageTLS = iota
	pageCPEDSlot
	pageALSGlobal
	pageFrame
	// pageTable holds the OrderedHashMap at its end, so a table that claims
	// more than it holds runs into pageGuard.
	pageTable
	pageGuard
	pageWrapper
	pageRecord
	// pageObjects holds the heap objects only ever compared by address.
	pageObjects
	numPages
)

// Offsets within pageObjects.
const (
	objALS = iota * 64
	objDecoy
	objUndefined
	objTableMap
)

// nodeHash selects bucket 0 of the default two buckets.
const nodeHash = 0x2a

// recordSlotOffset is the record slot offset of Node.js 23 and later.
const recordSlotOffset = 32

// Word indexes into the OrderedHashMap FixedArray. Its header ends with the
// length word, then the counts and the bucket heads follow.
const (
	tableHeaderWords = support.NodeTCFixedArrayHeader / support.NodeTCTaggedSize
	tableLength      = tableHeaderWords - 1
	tableElements    = tableHeaderWords
	tableDeleted     = tableHeaderWords + 1
	tableBuckets     = tableHeaderWords + 2
	tableHeads       = tableHeaderWords + support.NodeTCHashCounts
)

func tagged(addr uint64) uint64 { return addr | support.V8HeapObjectTag }
func smi(v int64) uint64        { return uint64(v) << support.V8SmiValueShift }

// notSmi returns a tagged word that would read as v if taken for a Smi, so
// only the Smi check can reject it.
func notSmi(v int64) uint64 { return smi(v) | support.V8HeapObjectTag }

// nodeArena is memory in this process the walk reads, as the eBPF program runs
// in its context.
type nodeArena struct {
	mem      []byte
	pageSize int
}

func newNodeArena(t *testing.T) *nodeArena {
	t.Helper()
	pageSize := os.Getpagesize()
	mem, err := unix.Mmap(-1, 0, numPages*pageSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(mem) })
	return &nodeArena{mem: mem, pageSize: pageSize}
}

func (a *nodeArena) page(p int) []byte {
	return a.mem[p*a.pageSize : (p+1)*a.pageSize]
}

func (a *nodeArena) addr(p int) uint64 {
	return uint64(uintptr(unsafe.Pointer(&a.page(p)[0])))
}

func (a *nodeArena) obj(off int) uint64 {
	return a.addr(pageObjects) + uint64(off)
}

// tableAddr is where a table of n words starts.
func (a *nodeArena) tableAddr(n int) uint64 {
	return a.addr(pageGuard) - uint64(support.NodeTCTaggedSize*n)
}

func (a *nodeArena) putWords(addr uint64, words ...uint64) {
	off := int(addr - a.addr(0))
	for i, w := range words {
		binary.NativeEndian.PutUint64(a.mem[off+support.NodeTCTaggedSize*i:], w)
	}
}

// nodeImage is the memory a Node.js process publishes its thread context
// through, per design-docs/01861-nodejs-thread-context.
type nodeImage struct {
	a *nodeArena

	// The otel_thread_ctx_nodejs_v1 fields.
	cpedSlot, alsHandle, undefinedAddr uint64
	alsIdentityHash                    int32
	recordSlotOffset                   uint8

	// cped is the CPED slot value: the active frame.
	cped uint64
	// alsKey is the AsyncLocalStorage the v8::Global refers to.
	alsKey uint64
	// tablePtr is the JSMap's pointer to its OrderedHashMap, or 0 for the
	// table laid out below.
	tablePtr uint64
	// table is the OrderedHashMap FixedArray, header words included.
	table []uint64
	// wrapper is the wrapper JSObject.
	wrapper [8]uint64

	// unreadable lists the pages made inaccessible.
	unreadable []int
}

// newNodeImage returns the image of a frame with two entries in the published
// AsyncLocalStorage's bucket: a decoy at the chain head, then the wrapper.
func newNodeImage(a *nodeArena) *nodeImage {
	img := &nodeImage{
		a:                a,
		cpedSlot:         a.addr(pageCPEDSlot),
		alsHandle:        a.addr(pageALSGlobal),
		undefinedAddr:    tagged(a.obj(objUndefined)),
		alsIdentityHash:  nodeHash,
		recordSlotOffset: recordSlotOffset,
		cped:             tagged(a.addr(pageFrame)),
		alsKey:           tagged(a.obj(objALS)),
	}
	img.setTable(2, 2, 0)
	img.setHead(nodeHash, 1)
	img.setEntry(0, img.alsKey, img.wrapperValue(), -1)
	img.setEntry(1, tagged(a.obj(objDecoy)), img.undefinedAddr, 0)
	img.wrapper[recordSlotOffset/support.NodeTCTaggedSize] = img.record()
	return img
}

func (img *nodeImage) record() uint64       { return img.a.addr(pageRecord) }
func (img *nodeImage) wrapperValue() uint64 { return tagged(img.a.addr(pageWrapper)) }
func (img *nodeImage) decoy() uint64        { return tagged(img.a.obj(objDecoy)) }

// setTable replaces the table with an empty, consistent one.
func (img *nodeImage) setTable(buckets, elements, deleted int64) {
	capacity := support.NodeTCHashLoadFactor * buckets
	length := support.NodeTCHashCounts + buckets + support.NodeTCHashEntrySize*capacity
	img.table = make([]uint64, tableHeaderWords+length)
	img.table[0] = tagged(img.a.obj(objTableMap))
	img.table[tableLength] = smi(length)
	img.table[tableElements] = smi(elements)
	img.table[tableDeleted] = smi(deleted)
	img.table[tableBuckets] = smi(buckets)
	for i := range buckets {
		img.table[tableHeads+i] = smi(-1)
	}
}

func (img *nodeImage) buckets() int64 {
	return int64(img.table[tableBuckets] >> 32)
}

// setHead points the bucket hash selects at entry.
func (img *nodeImage) setHead(hash int32, entry int64) {
	img.table[tableHeads+int64(uint32(hash))&(img.buckets()-1)] = smi(entry)
}

func (img *nodeImage) entryIndex(entry int64) int64 {
	return tableHeads + img.buckets() + support.NodeTCHashEntrySize*entry
}

func (img *nodeImage) setEntry(entry int64, key, value uint64, chain int64) {
	i := img.entryIndex(entry)
	img.table[i] = key
	img.table[i+1] = value
	img.table[i+2] = smi(chain)
}

// setSingleEntry replaces the table with one of the given buckets holding only
// the published entry.
func (img *nodeImage) setSingleEntry(buckets int64) {
	img.setTable(buckets, 1, 0)
	img.setHead(nodeHash, 0)
	img.setEntry(0, img.alsKey, img.wrapperValue(), -1)
}

// publish writes the image into its arena.
func (img *nodeImage) publish(t *testing.T) {
	t.Helper()
	a := img.a

	tls := a.page(pageTLS)
	binary.NativeEndian.PutUint64(tls[0:], img.cpedSlot)
	binary.NativeEndian.PutUint64(tls[8:], img.alsHandle)
	binary.NativeEndian.PutUint32(tls[16:], uint32(img.alsIdentityHash))
	tls[20] = img.recordSlotOffset
	binary.NativeEndian.PutUint64(tls[24:], img.undefinedAddr)

	tableAddr := a.tableAddr(len(img.table))
	tablePtr := img.tablePtr
	if tablePtr == 0 {
		tablePtr = tagged(tableAddr)
	}
	a.putWords(a.addr(pageCPEDSlot), img.cped)
	a.putWords(a.addr(pageALSGlobal), img.alsKey)
	a.putWords(a.addr(pageFrame), tagged(a.obj(objTableMap)))
	a.putWords(a.addr(pageFrame)+support.NodeTCJSMapTableOffset, tablePtr)
	a.putWords(tableAddr, img.table...)
	a.putWords(a.addr(pageWrapper), img.wrapper[:]...)

	for _, p := range append([]int{pageGuard}, img.unreadable...) {
		require.NoError(t, unix.Mprotect(a.page(p), unix.PROT_NONE))
	}
}

// nodeTCRecord is raw_tracepoint_integration__node_tc_record loaded with the
// metrics map it counts failures in.
type nodeTCRecord struct {
	prog    *cebpf.Program
	metrics *cebpf.Map
}

func loadNodeTCRecord(t *testing.T) *nodeTCRecord {
	t.Helper()
	spec, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	var objs struct {
		Prog    *cebpf.Program `ebpf:"raw_tracepoint_integration__node_tc_record"`
		Metrics *cebpf.Map     `ebpf:"metrics"`
	}
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		_ = objs.Prog.Close()
		_ = objs.Metrics.Close()
	})
	return &nodeTCRecord{prog: objs.Prog, metrics: objs.Metrics}
}

// metric returns the value of the eBPF counter translated to id, summed over
// all CPUs.
func (n *nodeTCRecord) metric(t *testing.T, id metrics.MetricID) uint64 {
	t.Helper()
	key := uint32(slices.Index(support.MetricsTranslation, id))
	require.NotEqual(t, uint32(0xffffffff), key, "no eBPF metric for %v", id)
	var perCPU []uint64
	require.NoError(t, n.metrics.Lookup(&key, &perCPU))
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

// nodeTCResult is the outcome of one walk.
type nodeTCResult struct {
	// ret is one of support.NodeTCTest*.
	ret uint32
	// The failure counters the walk incremented.
	errReadTLS, errRead, errInvalid uint64
}

// counters returns the current values of the failure counters.
func (n *nodeTCRecord) counters(t *testing.T) nodeTCResult {
	t.Helper()
	return nodeTCResult{
		errReadTLS: n.metric(t, metrics.IDUnwindThreadContextErrReadTlsPtr),
		errRead:    n.metric(t, metrics.IDUnwindThreadContextNodeErrRead),
		errInvalid: n.metric(t, metrics.IDUnwindThreadContextNodeErrInvalid),
	}
}

func (n *nodeTCRecord) run(t *testing.T, img *nodeImage) nodeTCResult {
	t.Helper()
	before := n.counters(t)
	ret, err := n.prog.Run(&cebpf.RunOptions{
		Context: []uint64{img.a.addr(pageTLS), img.record()},
	})
	require.NoError(t, err)
	after := n.counters(t)
	return nodeTCResult{
		ret:        ret,
		errReadTLS: after.errReadTLS - before.errReadTLS,
		errRead:    after.errRead - before.errRead,
		errInvalid: after.errInvalid - before.errInvalid,
	}
}

func TestNodeThreadContextRecord(t *testing.T) {
	n := loadNodeTCRecord(t)

	// The outcomes a walk can end in.
	var (
		found   = nodeTCResult{ret: support.NodeTCTestExpected}
		none    = nodeTCResult{ret: support.NodeTCTestNone}
		readTLS = nodeTCResult{errReadTLS: 1} // the discovery struct is unreadable
		readErr = nodeTCResult{errRead: 1}    // a V8 object is unreadable
		invalid = nodeTCResult{errInvalid: 1} // a V8 object is inconsistent
	)

	tests := map[string]struct {
		mutate func(*nodeImage)
		want   nodeTCResult
	}{
		"found after following the chain": {
			want: found,
		},
		"found at the chain head": {
			mutate: func(img *nodeImage) { img.setHead(nodeHash, 0) },
			want:   found,
		},
		"found with Node.js 22 record slot offset": {
			mutate: func(img *nodeImage) {
				img.recordSlotOffset = 24
				img.wrapper = [8]uint64{}
				img.wrapper[img.recordSlotOffset/support.NodeTCTaggedSize] = img.record()
			},
			want: found,
		},
		"found in a larger table": {
			mutate: func(img *nodeImage) { img.setSingleEntry(8) },
			want:   found,
		},
		"found with a negative identity hash": {
			mutate: func(img *nodeImage) {
				img.alsIdentityHash = -1
				img.setHead(nodeHash, -1)
				img.setHead(-1, 0)
			},
			want: found,
		},
		"found past a deleted entry": {
			// Deleted entries keep their index, so used = elements + deleted
			// bounds the walk rather than elements alone.
			mutate: func(img *nodeImage) {
				img.table[tableElements] = smi(1)
				img.table[tableDeleted] = smi(1)
				img.setHead(nodeHash, 1)
				img.setEntry(0, img.decoy(), img.undefinedAddr, -1)
				img.setEntry(1, img.alsKey, img.wrapperValue(), 0)
			},
			want: found,
		},

		// The early exits of a thread with nothing to report.
		"gate closed": {
			mutate: func(img *nodeImage) {
				// Nothing else may be used, so make it all unreadable.
				img.cpedSlot = 0
				img.unreadable = []int{pageCPEDSlot, pageALSGlobal, pageFrame,
					pageTable, pageWrapper}
			},
			want: none,
		},
		"no frame active": {
			mutate: func(img *nodeImage) { img.cped = img.undefinedAddr },
			want:   none,
		},
		"key absent from its bucket": {
			mutate: func(img *nodeImage) { img.setHead(nodeHash, -1) },
			want:   none,
		},
		"key in another bucket": {
			mutate: func(img *nodeImage) { img.alsIdentityHash = nodeHash + 1 },
			want:   none,
		},
		"detached": {
			mutate: func(img *nodeImage) {
				img.setEntry(0, img.alsKey, img.undefinedAddr, -1)
			},
			want: none,
		},
		"record slot zeroed": {
			mutate: func(img *nodeImage) { img.wrapper = [8]uint64{} },
			want:   none,
		},

		// A rehash clobbers bucket heads with indexes of deleted entries:
		// the lookup misses rather than fails.
		"bucket head not a Smi": {
			// Read as a Smi, it would lead straight to the published entry.
			mutate: func(img *nodeImage) { img.table[tableHeads] = notSmi(0) },
			want:   none,
		},
		"bucket head past the used entries": {
			mutate: func(img *nodeImage) { img.setHead(nodeHash, 2) },
			want:   none,
		},
		"chain link past the used entries": {
			mutate: func(img *nodeImage) {
				img.setEntry(1, img.decoy(), img.undefinedAddr, 3)
			},
			want: none,
		},
		"chain link not a Smi": {
			mutate: func(img *nodeImage) {
				// Read as a Smi, it would lead on to the published entry.
				img.table[img.entryIndex(1)+2] = notSmi(0)
			},
			want: none,
		},
		"cyclic chain": {
			mutate: func(img *nodeImage) {
				img.setEntry(0, img.decoy(), img.undefinedAddr, 1)
				img.setEntry(1, img.decoy(), img.undefinedAddr, 0)
			},
			want: none,
		},

		// Unreadable memory anywhere on the walk.
		"discovery struct unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageTLS} },
			want:   readTLS,
		},
		"CPED slot unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageCPEDSlot} },
			want:   readErr,
		},
		"AsyncLocalStorage handle unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageALSGlobal} },
			want:   readErr,
		},
		"frame unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageFrame} },
			want:   readErr,
		},
		"table unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageTable} },
			want:   readErr,
		},
		"entries beyond the readable table": {
			// The length claims entries that run into the guard page.
			mutate: func(img *nodeImage) {
				img.table = img.table[:img.entryIndex(0)]
			},
			want: readErr,
		},
		"wrapper unreadable": {
			mutate: func(img *nodeImage) { img.unreadable = []int{pageWrapper} },
			want:   readErr,
		},

		// Inconsistent V8 objects, rejected rather than followed.
		"record slot offset misaligned": {
			mutate: func(img *nodeImage) { img.recordSlotOffset = 33 },
			want:   invalid,
		},
		"frame not a heap object": {
			mutate: func(img *nodeImage) { img.cped = smi(1) },
			want:   invalid,
		},
		"table not a heap object": {
			mutate: func(img *nodeImage) { img.tablePtr = smi(1) },
			want:   invalid,
		},
		"length not a Smi": {
			mutate: func(img *nodeImage) { img.table[tableLength] = notSmi(17) },
			want:   invalid,
		},
		"element count a pointer to the rehashed table": {
			mutate: func(img *nodeImage) {
				img.table[tableElements] = tagged(img.a.obj(objTableMap))
			},
			want: invalid,
		},
		// The other non-Smi cases read as consistent values if taken for Smis.
		"element count not a Smi": {
			mutate: func(img *nodeImage) { img.table[tableElements] = notSmi(2) },
			want:   invalid,
		},
		"deleted count not a Smi": {
			mutate: func(img *nodeImage) { img.table[tableDeleted] = notSmi(0) },
			want:   invalid,
		},
		"bucket count not a Smi": {
			mutate: func(img *nodeImage) { img.table[tableBuckets] = notSmi(2) },
			want:   invalid,
		},
		// The bucket count cases are otherwise consistent, so only the bucket
		// count check can reject them.
		"bucket count not a power of two": {
			mutate: func(img *nodeImage) { img.setSingleEntry(3) },
			want:   invalid,
		},
		"bucket count zero": {
			mutate: func(img *nodeImage) {
				img.table[tableElements] = smi(0)
				img.table[tableBuckets] = smi(0)
			},
			want: invalid,
		},
		"bucket count negative": {
			mutate: func(img *nodeImage) {
				img.table[tableElements] = smi(0)
				img.table[tableBuckets] = smi(-2)
			},
			want: invalid,
		},
		"element count negative": {
			mutate: func(img *nodeImage) { img.table[tableElements] = smi(-1) },
			want:   invalid,
		},
		"deleted count negative": {
			mutate: func(img *nodeImage) { img.table[tableDeleted] = smi(-1) },
			want:   invalid,
		},
		"more entries than capacity": {
			mutate: func(img *nodeImage) {
				img.table[tableElements] = smi(3)
				img.table[tableDeleted] = smi(2)
			},
			want: invalid,
		},
		"length too short for the buckets": {
			mutate: func(img *nodeImage) { img.table[tableLength] = smi(16) },
			want:   invalid,
		},
		"value not a heap object": {
			mutate: func(img *nodeImage) {
				img.setEntry(0, img.alsKey, smi(1), -1)
			},
			want: invalid,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			img := newNodeImage(newNodeArena(t))
			if tc.mutate != nil {
				tc.mutate(img)
			}
			img.publish(t)
			assert.Equal(t, tc.want, n.run(t, img))
		})
	}
}
