// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"sync/atomic"
	"unicode/utf8"

	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

// customLabelValidator validates custom label keys and values extracted from
// eBPF and tracks how many are dropped due to invalid UTF-8. The zero value is
// ready to use. Methods take pointer receivers (atomic ops require an
// addressable counter), so embed as a value field on a struct held by pointer.
type customLabelValidator struct {
	droppedInvalidName  atomic.Int64
	droppedInvalidValue atomic.Int64
}

// validateKey enforces strict UTF-8 validity on a custom label key. Any invalid
// byte (or an empty key) returns ok=false and bumps the drop counter, signaling
// the caller to drop the label. A corrupted key would silently group unrelated
// samples under a garbage name, so strictness is intentional here. The returned
// slice aliases buf; copy or intern before the buffer is reused.
func (v *customLabelValidator) validateKey(buf []byte) ([]byte, bool) {
	b := stringutil.CString(buf)
	if len(b) == 0 || !utf8.Valid(b) {
		v.droppedInvalidName.Add(1)
		return nil, false
	}
	return b, true
}

// validateValue is lenient on a custom label value: fixed-width eBPF buffers
// can clip a multi-byte rune in half, so on invalid trailing bytes we salvage
// the longest valid UTF-8 prefix rather than discard the whole label. ok=false
// (and bumping the drop counter) fires only when the salvage is empty, i.e.
// the input was non-empty garbage rather than mid-rune truncation. The returned
// slice aliases buf; copy or intern before the buffer is reused.
func (v *customLabelValidator) validateValue(buf []byte) ([]byte, bool) {
	b := stringutil.CString(buf)
	pos := len(b)
	if !utf8.Valid(b) {
		// Walk forward; stop at the first invalid byte. This recovers the entire
		// valid prefix of a mid-rune truncation in one pass.
		pos = 0
		for pos < len(b) {
			r, size := utf8.DecodeRune(b[pos:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			pos += size
		}
		if pos == 0 {
			v.droppedInvalidValue.Add(1)
			return nil, false
		}
	}
	return b[:pos], true
}

// getAndResetMetrics reports and resets the counters of custom labels dropped
// due to an invalid name or value since the previous call.
func (v *customLabelValidator) getAndResetMetrics() []metrics.Metric {
	return []metrics.Metric{
		{
			ID:    metrics.IDGoLabelsDroppedInvalidName,
			Value: metrics.MetricValue(v.droppedInvalidName.Swap(0)),
		},
		{
			ID:    metrics.IDGoLabelsDroppedInvalidValue,
			Value: metrics.MetricValue(v.droppedInvalidValue.Swap(0)),
		},
	}
}
