/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package pfelf

import (
	"os"
	"testing"

	"github.com/elastic/otel-profiling-agent/testsupport"
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
