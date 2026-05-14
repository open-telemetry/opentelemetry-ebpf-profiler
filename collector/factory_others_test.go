// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package collector

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func TestCreateProfilesReceiverUnsupported(t *testing.T) {
	typ, err := component.NewType("ProfilesReceiver")
	require.NoError(t, err)
	_, err = BuildProfilesReceiver()(
		t.Context(),
		receivertest.NewNopSettings(typ),
		NewFactory().CreateDefaultConfig(),
		consumertest.NewNop(),
	)
	require.Error(t, err)
}
