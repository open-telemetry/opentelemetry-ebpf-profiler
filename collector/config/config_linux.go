// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func validatePlatformConstraints(cfg *Config) error {
	if cfg.NoKernelVersionCheck {
		return nil
	}

	major, minor, patch, err := linux.GetCurrentKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}

	var minMajor, minMinor uint32
	minMajor, minMinor = 5, 10
	if major < minMajor || (major == minMajor && minor < minMinor) {
		return fmt.Errorf("host Agent requires kernel version "+
			"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
	}

	return nil
}

func validateTracerConfig(cfg *Config) error {
	if cfg.ProbabilisticThreshold < 1 ||
		cfg.ProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return fmt.Errorf(
			"invalid argument for probabilistic-threshold. Value "+
				"should be between 1 and %d",
			tracer.ProbabilisticThresholdMax,
		)
	}
	return nil
}
