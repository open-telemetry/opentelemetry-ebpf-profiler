//go:build !debugtracer

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support

// debugtracer_dummy.go satisfies build requirements where the eBPF debug tracers
// file does not exist.
var debugTracerData []byte
