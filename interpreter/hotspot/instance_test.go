/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hotspot

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/elastic/go-freelru"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/remotememory"
	"github.com/elastic/otel-profiling-agent/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJavaSymbolExtraction(t *testing.T) {
	rm := remotememory.NewProcessVirtualMemory(util.PID(os.Getpid()))
	id := hotspotData{}
	vmd, _ := id.GetOrInit(func() (hotspotVMData, error) {
		vmd := hotspotVMData{}
		vmd.vmStructs.Symbol.Length = 2
		vmd.vmStructs.Symbol.Body = 4
		return vmd, nil
	})

	addrToSymbol, err := freelru.New[libpf.Address, string](2, libpf.Address.Hash32)
	require.NoError(t, err, "symbol cache failed")

	ii := hotspotInstance{
		d:            &id,
		rm:           rm,
		addrToSymbol: addrToSymbol,
		prefixes:     libpf.Set[lpm.Prefix]{},
		stubs:        map[libpf.Address]StubRoutine{},
	}
	maxLength := 1024
	sym := make([]byte, vmd.vmStructs.Symbol.Body+uint(maxLength))
	str := strings.Repeat("a", maxLength)
	copy(sym[vmd.vmStructs.Symbol.Body:], str)
	for i := 0; i <= maxLength; i++ {
		binary.LittleEndian.PutUint16(sym[vmd.vmStructs.Symbol.Length:], uint16(i))
		address := libpf.Address(uintptr(unsafe.Pointer(&sym[0])))
		got := ii.getSymbol(address)
		assert.Equal(t, str[:i], got, "symbol length %d mismatched read", i)
		ii.addrToSymbol.Purge()
	}
}
