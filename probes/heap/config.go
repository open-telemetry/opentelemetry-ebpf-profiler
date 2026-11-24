// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import "fmt"

const (
	defaultMapScaleFactor = 2
	maxMapScaleFactor     = 8
)

// Config configures the heap profiling probe.
type Config struct {
	MapScaleFactor uint `mapstructure:"map_scale_factor"`
}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	if c.MapScaleFactor > maxMapScaleFactor {
		return fmt.Errorf(
			"heap eBPF map scaling factor %d exceeds limit (max: %d)",
			c.MapScaleFactor, maxMapScaleFactor,
		)
	}
	return nil
}
