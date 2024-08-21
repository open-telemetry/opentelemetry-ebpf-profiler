package profilingreceiver

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
			config: createDefaultConfig(),
		},
		{
			name:      "Nil config",
			wantError: errInvalidConfig,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := createProfilesReceiver(
				context.Background(),
				receivertest.NewNopSettings(),
				tt.config,
				consumertest.NewNop(),
			)
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}
