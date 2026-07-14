// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build (!amd64 && !arm64) || windows

// Package interpreterconfig aggregates per-interpreter configuration.
// On platforms where the interpreter packages are not available (Windows,
// non-amd64/arm64 architectures) this is a stub.
package interpreterconfig // import "go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"

// Config holds configuration for all interpreters.
// This is a stub on platforms where interpreter packages are unavailable.
type Config struct{}

// AllInterpreters returns a Config with all interpreters enabled.
func AllInterpreters() Config { return Config{} }

// NoInterpreters returns a Config with all interpreters disabled.
func NoInterpreters() Config { return Config{} }

// IsMapEnabled always returns false on unsupported platforms.
func (cfg *Config) IsMapEnabled(_ string) bool { return false }
