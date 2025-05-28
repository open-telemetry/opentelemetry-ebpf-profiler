//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

// On AMD64, the TLS offset for the goroutine structure is at a fixed offset
func extractTLSGOffset(*pfelf.File) (int32, error) {
	// https://github.com/golang/go/blob/396a48bea6f/src/cmd/compile/internal/amd64/ssa.go#L174
	return -8, nil
}
