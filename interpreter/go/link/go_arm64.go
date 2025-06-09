//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package link // import "go.opentelemetry.io/ebpf-profiler/interpreter/go/link"

/*
#cgo LDFLAGS: ${SRCDIR}/../../../target/aarch64-unknown-linux-musl/release/libsymblib_capi.a
*/
import "C"
