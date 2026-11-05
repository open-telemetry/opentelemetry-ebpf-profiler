// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hotspot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestJavaSymbolExtraction(t *testing.T) {
	id := hotspotData{}
	vmd, _ := id.GetOrInit(func() (hotspotVMData, error) {
		vmd := hotspotVMData{}
		vmd.vmStructs.Symbol.Length = 2
		vmd.vmStructs.Symbol.Body = 4
		return vmd, nil
	})

	maxLength := 1024
	sym := make([]byte, vmd.vmStructs.Symbol.Body+uint(maxLength))
	rd := bytes.NewReader(sym)
	rm := remotememory.RemoteMemory{ReaderAt: rd}

	instance, err := id.Attach(nil, 0, 0, rm)
	require.NoError(t, err, "symbol cache failed")
	ii := instance.(*hotspotInstance)

	str := strings.Repeat("a", maxLength)
	copy(sym[vmd.vmStructs.Symbol.Body:], str)
	for i := 0; i <= maxLength; i++ {
		binary.LittleEndian.PutUint16(sym[vmd.vmStructs.Symbol.Length:], uint16(i))
		got := ii.getSymbol(0)
		assert.Equal(t, str[:i], got.String(), "symbol length %d mismatched read", i)
		ii.addrToSymbol.Purge()
	}
}

// TestStubsMapRace verifies there is no data race on concurrent
// read and write access to d.stubs.
func TestStubsMapRace(t *testing.T) {
	const (
		fieldName      = 0
		fieldCodeBegin = 8
	)

	const (
		codeBeginAddr = 0x1000
		numStubs      = 50
		stubSpacing   = 128
		// based on value defined in findStubBounds() in stubs.go
		maxStubLen = 8 * 1024
		blobName   = "StubCode"
	)

	const (
		slotsBase  = 16
		slotsEnd   = slotsBase + numStubs*8
		nameBase   = slotsEnd
		codeBase   = 1024
		bufSize    = codeBase + numStubs*stubSpacing + maxStubLen
		iterations = 500
	)

	buf := make([]byte, bufSize)
	binary.LittleEndian.PutUint64(buf[fieldName:], nameBase)
	binary.LittleEndian.PutUint64(buf[fieldCodeBegin:], codeBeginAddr)
	copy(buf[nameBase:], blobName)

	catchAll := make(map[string]libpf.Address, numStubs)
	for i := range numStubs {
		slot := libpf.Address(slotsBase + i*8)
		stubAddr := uint64(codeBase + i*stubSpacing)
		binary.LittleEndian.PutUint64(buf[slot:], stubAddr)
		catchAll[fmt.Sprintf("_stub_%d", i)] = slot
	}

	rd := bytes.NewReader(buf)
	rm := remotememory.RemoteMemory{ReaderAt: rd}

	id := hotspotData{}
	vmd, _ := id.GetOrInit(func() (hotspotVMData, error) {
		vmd := hotspotVMData{}
		vmd.vmStructs.CodeBlob.Name = fieldName
		vmd.vmStructs.CodeBlob.CodeBegin = fieldCodeBegin
		vmd.vmStructs.StubRoutines.CatchAll = catchAll
		return vmd, nil
	})

	instance, err := id.Attach(nil, 0, 0, rm)
	require.NoError(t, err)
	ii := instance.(*hotspotInstance)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iterations {
			ii.updateStubMappings(vmd, nil, 0)
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			ii.addrToStubName.Purge()
			ii.getStubName(0, 0)
		}
	}()

	wg.Wait()
}

// TestVMStructsFieldKinds verifies that all vmStructs fields have kinds handled by
// parseIntrospection and forEachItem. Update those functions if this test fails.
func TestVMStructsFieldKinds(t *testing.T) {
	var checkType func(rt reflect.Type, prefix string)
	checkType = func(rt reflect.Type, prefix string) {
		for f := range rt.Fields() {
			fullName := prefix + f.Name
			switch f.Type.Kind() {
			case reflect.Struct:
				checkType(f.Type, fullName+".")
			case reflect.Uint, reflect.Uint64, reflect.Uintptr, reflect.Map:
				// handled by parseIntrospection and forEachItem
			default:
				t.Errorf("unsupported field kind in vmStructs: %s is %v; "+
					"update parseIntrospection and forEachItem to handle it",
					fullName, f.Type.Kind())
			}
		}
	}
	checkType(reflect.TypeOf(hotspotVMData{}.vmStructs), "")
}

// TestUpdateStubMappingsSkipsKnownStubs verifies that a repeated sync does not
// redo the expensive per-stub boundary sweep and does not change tracked stubs.
func TestUpdateStubMappingsSkipsKnownStubs(t *testing.T) {
	const (
		numStubs    = 20
		slotsBase   = 16
		codeBase    = 1024
		stubSpacing = 128
		bufSize     = codeBase + numStubs*stubSpacing + 8*1024
	)

	buf := make([]byte, bufSize)
	catchAll := make(map[string]libpf.Address, numStubs)
	for i := range numStubs {
		slot := libpf.Address(slotsBase + i*8)
		binary.LittleEndian.PutUint64(buf[slot:], uint64(codeBase+i*stubSpacing))
		catchAll[fmt.Sprintf("_stub_%d", i)] = slot
	}

	cr := &countingReaderAt{r: bytes.NewReader(buf)}
	rm := remotememory.RemoteMemory{ReaderAt: cr}

	id := hotspotData{}
	vmd, _ := id.GetOrInit(func() (hotspotVMData, error) {
		vmd := hotspotVMData{}
		vmd.vmStructs.StubRoutines.CatchAll = catchAll
		return vmd, nil
	})
	instance, err := id.Attach(nil, 0, 0, rm)
	require.NoError(t, err)
	ii := instance.(*hotspotInstance)

	ii.updateStubMappings(vmd, nil, 0)
	firstReads := cr.reads
	stubs := ii.stubs.RLock()
	first := maps.Clone(*stubs)
	ii.stubs.RUnlock(&stubs)
	require.Len(t, first, numStubs)

	cr.reads = 0
	ii.updateStubMappings(vmd, nil, 0)
	stubs = ii.stubs.RLock()
	second := maps.Clone(*stubs)
	ii.stubs.RUnlock(&stubs)

	assert.Equal(t, first, second)
	// Second pass only re-reads the stub entry pointers, no boundary sweeps.
	assert.LessOrEqual(t, cr.reads, numStubs)
	assert.Greater(t, firstReads, cr.reads)
}

// newStubSyncInstance creates an instance with numStubs stub slots in a fake memory
// image. Only the first `initial` slots are populated, populate() fills the others.
func newStubSyncInstance(t *testing.T, numStubs, initial int) (
	ii *hotspotInstance, vmd *hotspotVMData, cr *countingReaderAt, populate func(),
) {
	t.Helper()
	const (
		slotsBase   = 16
		codeBase    = 1024
		stubSpacing = 128
	)

	buf := make([]byte, codeBase+numStubs*stubSpacing+8*1024)
	catchAll := make(map[string]libpf.Address, numStubs)
	setSlot := func(i int) {
		binary.LittleEndian.PutUint64(buf[slotsBase+i*8:], uint64(codeBase+i*stubSpacing))
	}
	for i := range numStubs {
		catchAll[fmt.Sprintf("_stub_%d", i)] = libpf.Address(slotsBase + i*8)
		if i < initial {
			setSlot(i)
		}
	}

	cr = &countingReaderAt{r: bytes.NewReader(buf)}
	id := hotspotData{}
	vmd, _ = id.GetOrInit(func() (hotspotVMData, error) {
		v := hotspotVMData{}
		v.vmStructs.StubRoutines.CatchAll = catchAll
		return v, nil
	})
	instance, err := id.Attach(nil, 0, 0, remotememory.RemoteMemory{ReaderAt: cr})
	require.NoError(t, err)

	return instance.(*hotspotInstance), vmd, cr, func() {
		for i := initial; i < numStubs; i++ {
			setSlot(i)
		}
	}
}

func stubCount(ii *hotspotInstance) int {
	stubs := ii.stubs.RLock()
	defer ii.stubs.RUnlock(&stubs)
	return len(*stubs)
}

// TestSyncStubMappingsTwoPasses verifies that stubs are scanned once after attach and
// once after the first Java frame, and never again.
func TestSyncStubMappingsTwoPasses(t *testing.T) {
	const numStubs, initial = 20, 10
	ii, vmd, cr, populate := newStubSyncInstance(t, numStubs, initial)

	// Pass 1: stubs generated so far are found.
	ii.syncStubMappings(vmd, nil, 0)
	assert.Equal(t, initial, stubCount(ii))

	// Boot continues and generates the remaining stubs; without a Java frame
	// there is no second pass yet.
	populate()
	cr.reads = 0
	ii.syncStubMappings(vmd, nil, 0)
	assert.Zero(t, cr.reads, "no scan expected before the first Java frame")
	assert.Equal(t, initial, stubCount(ii))

	// Pass 2: runs after the first Java frame and picks up the late stubs.
	ii.markFrameSeen()
	ii.syncStubMappings(vmd, nil, 0)
	assert.Equal(t, numStubs, stubCount(ii))

	// No further scans.
	cr.reads = 0
	ii.syncStubMappings(vmd, nil, 0)
	ii.syncStubMappings(vmd, nil, 0)
	assert.Zero(t, cr.reads, "no scan expected after both passes")
}

// TestSyncStubMappingsFrameAlreadySeen verifies that a single scan is enough when
// the first Java frame was already received before the first scan.
func TestSyncStubMappingsFrameAlreadySeen(t *testing.T) {
	const numStubs = 20
	ii, vmd, cr, _ := newStubSyncInstance(t, numStubs, numStubs)
	ii.markFrameSeen()

	ii.syncStubMappings(vmd, nil, 0)
	assert.Equal(t, numStubs, stubCount(ii))

	cr.reads = 0
	ii.syncStubMappings(vmd, nil, 0)
	assert.Zero(t, cr.reads, "second pass is redundant after a post-boot scan")
}

// hookReaderAt calls hook once, before serving the first read at or above minOff.
type hookReaderAt struct {
	io.ReaderAt
	minOff int64
	hook   func()
}

func (h *hookReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if h.hook != nil && off >= h.minOff {
		hook := h.hook
		h.hook = nil
		hook()
	}
	return h.ReaderAt.ReadAt(p, off)
}

// TestSyncStubMappingsFrameDuringScan verifies that a Java frame arriving while a
// scan is running triggers another scan, which picks up stubs generated meanwhile.
func TestSyncStubMappingsFrameDuringScan(t *testing.T) {
	const numStubs, initial = 20, 10
	ii, vmd, cr, populate := newStubSyncInstance(t, numStubs, initial)
	ii.rm = remotememory.RemoteMemory{ReaderAt: &hookReaderAt{
		ReaderAt: cr,
		// Stub pointers are read below this offset, stub code (boundary sweep) above.
		minOff: 1024,
		hook: func() {
			// Boot finishes and the first frame arrives in the middle of the scan,
			// after the stub pointers were read.
			populate()
			ii.markFrameSeen()
		},
	}}

	ii.syncStubMappings(vmd, nil, 0)
	assert.Equal(t, initial, stubCount(ii), "scan started before the stubs were generated")

	ii.syncStubMappings(vmd, nil, 0)
	assert.Equal(t, numStubs, stubCount(ii))
}
