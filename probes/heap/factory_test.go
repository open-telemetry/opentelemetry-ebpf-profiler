// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import "testing"

func TestNewFactory(t *testing.T) {
	if factory := NewFactory(); factory == nil {
		t.Fatal("NewFactory returned nil")
	}
}
