//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import "context"

type bpfSymbolizerPlatform struct{}

// startMonitor is unsupported on non-Linux platforms.
func (s *bpfSymbolizer) startMonitor(_ context.Context, _ []int) error {
	return nil
}

// close frees resources associated with bpfSymbolizer.
func (s *bpfSymbolizer) close() {}
