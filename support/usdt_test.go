// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/usdt"
)

func TestUSDTConstantsMatchBPF(t *testing.T) {
	assert.Equal(t, usdt.MaxArguments, support.USDTMaxArguments)

	argumentKinds := []struct {
		goValue  usdt.ArgumentKind
		bpfValue uint8
	}{
		{usdt.ArgumentConstant, support.USDTArgumentConstant},
		{usdt.ArgumentRegister, support.USDTArgumentRegister},
		{usdt.ArgumentRegisterDereference, support.USDTArgumentRegisterDereference},
	}
	for _, kind := range argumentKinds {
		assert.EqualValues(t, kind.goValue, kind.bpfValue)
	}

	assert.EqualValues(t, 80, support.USDTAMD64PtRegsRAXOffset)
	assert.EqualValues(t, 128, support.USDTAMD64PtRegsRIPOffset)
	assert.EqualValues(t, 152, support.USDTAMD64PtRegsRSPOffset)
	assert.EqualValues(t, 0, support.USDTARM64PtRegsX0Offset)
	assert.EqualValues(t, 8, support.USDTARM64PtRegsRegisterSize)
	assert.EqualValues(t, 248, support.USDTARM64PtRegsSPOffset)
	assert.EqualValues(t, 256, support.USDTARM64PtRegsPCOffset)
}
