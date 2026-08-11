// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import "go.opentelemetry.io/collector/component"

var (
	// Type is the component type of the kprobe extension.
	Type = component.MustNewType("kprobe")

	stability = component.StabilityLevelDevelopment
)
