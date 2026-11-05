// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

// Option is a placeholder for platform-specific receiver options.
// The profiling receiver is only functional on Linux amd64/arm64.
type Option interface{}
