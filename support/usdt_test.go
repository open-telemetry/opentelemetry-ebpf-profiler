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
	assert.EqualValues(t, usdt.MaxArguments, support.USDTMaxArguments)

	argumentKinds := []struct {
		goValue  usdt.ArgumentKind
		bpfValue uint32
	}{
		{usdt.ArgumentConstant, support.USDTArgumentConstant},
		{usdt.ArgumentRegister, support.USDTArgumentRegister},
		{usdt.ArgumentRegisterDereference, support.USDTArgumentRegisterDereference},
	}
	for _, kind := range argumentKinds {
		assert.EqualValues(t, kind.goValue, kind.bpfValue)
	}

	registers := []struct {
		goValue  usdt.Register
		bpfValue uint8
	}{
		{usdt.RegisterNone, support.USDTRegisterNone},
		{usdt.RegisterRAX, support.USDTRegisterRAX},
		{usdt.RegisterRBX, support.USDTRegisterRBX},
		{usdt.RegisterRCX, support.USDTRegisterRCX},
		{usdt.RegisterRDX, support.USDTRegisterRDX},
		{usdt.RegisterRSI, support.USDTRegisterRSI},
		{usdt.RegisterRDI, support.USDTRegisterRDI},
		{usdt.RegisterRBP, support.USDTRegisterRBP},
		{usdt.RegisterRSP, support.USDTRegisterRSP},
		{usdt.RegisterR8, support.USDTRegisterR8},
		{usdt.RegisterR9, support.USDTRegisterR9},
		{usdt.RegisterR10, support.USDTRegisterR10},
		{usdt.RegisterR11, support.USDTRegisterR11},
		{usdt.RegisterR12, support.USDTRegisterR12},
		{usdt.RegisterR13, support.USDTRegisterR13},
		{usdt.RegisterR14, support.USDTRegisterR14},
		{usdt.RegisterR15, support.USDTRegisterR15},
		{usdt.RegisterRIP, support.USDTRegisterRIP},
		{usdt.RegisterX0, support.USDTRegisterX0},
		{usdt.RegisterX30, support.USDTRegisterX30},
		{usdt.RegisterSP, support.USDTRegisterSP},
		{usdt.RegisterPC, support.USDTRegisterPC},
	}
	for _, register := range registers {
		assert.EqualValues(t, register.goValue, register.bpfValue)
	}
}
