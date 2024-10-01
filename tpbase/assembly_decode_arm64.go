//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"

func GetAnalyzers() []Analyzer {
	return arm64GetAnalyzers()
}
