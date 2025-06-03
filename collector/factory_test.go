// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	require.NotNil(t, f)
}

func TestCreateProfilesReceiver(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config component.Config

		wantError error
	}{
		{
			name:   "Default config",
			config: defaultConfig(),
		},
		{
			name:      "Nil config",
			wantError: errInvalidConfig,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			typ, err := component.NewType("ProfilesReceiver")
			require.ErrorIs(t, err, nil)
			_, err = createProfilesReceiver(
				context.Background(),
				receivertest.NewNopSettings(typ),
				tt.config,
				consumertest.NewNop(),
			)
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}
