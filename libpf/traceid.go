// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

type SpanID [8]byte
type TraceID [16]byte

var InvalidSpanID = SpanID{0, 0, 0, 0, 0, 0, 0, 0}
var InvalidTraceID = TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
