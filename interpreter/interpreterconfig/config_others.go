// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

// Package interpreterconfig aggregates per-interpreter configuration.
package interpreterconfig // import "go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"

// Config holds configuration for all interpreters.
// On non-Linux platforms this is a stub as this project only runs on Linux.
type Config struct{}

// AllInterpreters returns a Config with all interpreters enabled.
func AllInterpreters() Config { return Config{} }

// NoInterpreters returns a Config with all interpreters disabled.
func NoInterpreters() Config { return Config{} }

// IsMapEnabled always returns false on non-Linux platforms.
func (cfg *Config) IsMapEnabled(_ string) bool { return false }
