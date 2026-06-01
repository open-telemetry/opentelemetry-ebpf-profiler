// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hotspot

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
