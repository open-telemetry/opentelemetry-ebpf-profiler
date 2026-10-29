// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestUSDTPtRegsOffsets(t *testing.T) {
	assert.EqualValues(t, 80, support.USDTAMD64PtRegsRAXOffset)
	assert.EqualValues(t, 128, support.USDTAMD64PtRegsRIPOffset)
	assert.EqualValues(t, 152, support.USDTAMD64PtRegsRSPOffset)
	assert.EqualValues(t, 0, support.USDTARM64PtRegsX0Offset)
	assert.EqualValues(t, 8, support.USDTARM64PtRegsRegisterSize)
	assert.EqualValues(t, 248, support.USDTARM64PtRegsSPOffset)
	assert.EqualValues(t, 256, support.USDTARM64PtRegsPCOffset)
}
