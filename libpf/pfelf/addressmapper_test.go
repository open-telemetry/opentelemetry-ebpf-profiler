// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"os"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertFileToVA(t *testing.T, mapper AddressMapper, fileAddress, virtualAddress uint64) {
	mappedAddress, ok := mapper.FileOffsetToVirtualAddress(fileAddress)
	assert.True(t, ok)
	assert.Equal(t, virtualAddress, mappedAddress)
}

func TestAddressMapper(t *testing.T) {
	debugExePath, err := testsupport.WriteTestExecutable2()
	require.NoError(t, err)
	defer os.Remove(debugExePath)

	ef, err := Open(debugExePath)
	require.NoError(t, err)

	mapper := ef.GetAddressMapper()
	assertFileToVA(t, mapper, 0x1000, 0x401000)
	assertFileToVA(t, mapper, 0x1010, 0x401010)
}
