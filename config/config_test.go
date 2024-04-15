/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"os"
	"testing"
)

func TestSetConfiguration(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	cfg := Config{
		ProjectID:       42,
		CacheDirectory:  cwd,
		EnvironmentType: "aws",
		MachineID:       "0xfeeddeadbeefbeef",
		SecretToken:     "secret",
		ValidatedTags:   "",
	}

	// Test setting environment to "aws".
	err = SetConfiguration(&cfg)
	if err != nil {
		t.Fatalf("failure to set environment to \"aws\"")
	}

	cfg2 := cfg
	cfg2.EnvironmentType = "bla"
	err = SetConfiguration(&cfg2)
	if err == nil {
		t.Fatalf("expected failure using invalid environment (%s)", err)
	}

	cfg3 := cfg
	cfg3.MachineID = ""
	err = SetConfiguration(&cfg3)
	if err == nil {
		t.Fatalf("expected failure using empty machineID for environment (%s)", err)
	}

	cfg4 := cfg
	cfg4.EnvironmentType = ""
	err = SetConfiguration(&cfg4)
	if err == nil {
		t.Fatalf("expected failure using empty environment for machineID (%s)", err)
	}

	cfg5 := cfg
	cfg5.EnvironmentType = "aws"
	cfg5.SecretToken = ""
	err = SetConfiguration(&cfg5)
	if err == nil {
		t.Fatalf("expected failure using empty secretToken for environment")
	}
}
