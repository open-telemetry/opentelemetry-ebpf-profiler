package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControllerStart(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config *Config

		wantErr error
	}{
		{
			name: "with a nil config",
		},
		{
			name:   "with an empty config",
			config: &Config{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctlr := New(tt.config)

			err := ctlr.Start(context.Background())
			if tt.wantErr != nil {
				require.ErrorIs(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
