// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

const invalidSamplesPerSecond = 0

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
		{
			name:      "Invalid config",
			config:    Config{SamplesPerSecond: invalidSamplesPerSecond},
			wantError: fmt.Errorf("invalid sampling frequency: %d", invalidSamplesPerSecond),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			typ, err := component.NewType("ProfilesReceiver")
			require.NoError(t, err)
			_, err = BuildProfilesReceiver()(
				t.Context(),
				receivertest.NewNopSettings(typ),
				tt.config,
				consumertest.NewNop(),
			)

			// Handle nil errors
			if err != nil || tt.wantError != nil {
				require.ErrorAs(t, err, &tt.wantError)
			}
		})
	}
}
