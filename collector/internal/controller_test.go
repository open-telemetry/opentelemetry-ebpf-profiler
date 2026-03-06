//go:build !integration
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeController is a mock that always returns a configurable error on Start.
type fakeController struct {
	startErr error
}

func (f *fakeController) Start(_ context.Context) error { return f.startErr }
func (f *fakeController) Shutdown()                     {}

func TestStartAllowStartupFailure(t *testing.T) {
	startErr := errors.New("eBPF not available")

	tests := map[string]struct {
		startErr            error
		allowStartupFailure bool
		wantErr             bool
	}{
		"startup failure ignored when AllowStartupFailure is true": {
			startErr:            startErr,
			allowStartupFailure: true,
			wantErr:             false,
		},
		"startup failure propagated when AllowStartupFailure is false": {
			startErr:            startErr,
			allowStartupFailure: false,
			wantErr:             true,
		},
		"no error returned when Start succeeds": {
			startErr:            nil,
			allowStartupFailure: false,
			wantErr:             false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Controller{
				ctlr:                &fakeController{startErr: test.startErr},
				allowStartupFailure: test.allowStartupFailure,
			}
			err := c.Start(context.Background(), nil)
			if test.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, test.startErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
