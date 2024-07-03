/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hotspot

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/remotememory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	addrToSymbol, err := freelru.New[libpf.Address, string](2, libpf.Address.Hash32)
	require.NoError(t, err, "symbol cache failed")

	ii := hotspotInstance{
		d:            &id,
		rm:           rm,
		addrToSymbol: addrToSymbol,
		prefixes:     libpf.Set[lpm.Prefix]{},
		stubs:        map[libpf.Address]StubRoutine{},
	}

	str := strings.Repeat("a", maxLength)
	copy(sym[vmd.vmStructs.Symbol.Body:], str)
	for i := 0; i <= maxLength; i++ {
		binary.LittleEndian.PutUint16(sym[vmd.vmStructs.Symbol.Length:], uint16(i))
		got := ii.getSymbol(0)
		assert.Equal(t, str[:i], got, "symbol length %d mismatched read", i)
		ii.addrToSymbol.Purge()
	}
}
