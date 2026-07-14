// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import "errors"

func validatePlatformConstraints(_ *Config) error {
	return errors.New("profiling receiver is only supported on Linux and arm64 or amd64")

}

func validateTracerConfig(_ *Config) error {
	return errors.New("profiling receiver is only supported on Linux and arm64 or amd64")
}
