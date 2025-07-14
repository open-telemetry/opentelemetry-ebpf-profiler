//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"

func ExtractTSDInfoX64_64(_ []byte) (TSDInfo, error) {
	return TSDInfo{}, errArchNotImplemented
}

func ExtractTSDInfoNative(code []byte) (TSDInfo, error) {
	return extractTSDInfoARM(code)
}
