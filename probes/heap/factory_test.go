// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import "testing"

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	if factory == nil {
		t.Fatal("NewFactory returned nil")
	}

	cfg, ok := factory.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatal("default config has unexpected type")
	}
	if cfg.LiveHeapMaxEntriesPerPID != defaultLiveHeapMaxEntriesPerPID {
		t.Fatalf("default live heap limit: got %d, want %d",
			cfg.LiveHeapMaxEntriesPerPID, defaultLiveHeapMaxEntriesPerPID)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (&Config{LiveHeapMaxEntriesPerPID: -1}).Validate(); err == nil {
		t.Fatal("negative live heap limit should fail validation")
	}
	if err := (&Config{LiveHeapMaxEntriesPerPID: 0}).Validate(); err != nil {
		t.Fatalf("zero live heap limit should disable limiting: %v", err)
	}
}
