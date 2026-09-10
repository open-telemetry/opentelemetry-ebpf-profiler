// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"sync/atomic"
	"unicode/utf8"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
	"go.opentelemetry.io/ebpf-profiler/support"
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

type threadContextLabelMetrics struct {
	// Samples dropped whole, for want of a schema to name their key indices.
	droppedSamplesNoSchema atomic.Int64
	// Individual entries dropped from an otherwise decodable sample.
	droppedEntriesUndecodable atomic.Int64
}

func (m *threadContextLabelMetrics) getAndResetMetrics() []metrics.Metric {
	return []metrics.Metric{
		{
			ID:    metrics.IDThreadContextDroppedSamplesNoSchema,
			Value: metrics.MetricValue(m.droppedSamplesNoSchema.Swap(0)),
		},
		{
			ID:    metrics.IDThreadContextDroppedEntriesUndecodable,
			Value: metrics.MetricValue(m.droppedEntriesUndecodable.Swap(0)),
		},
	}
}

// goCustomLabels decodes the Go runtime/pprof variant of the Trace custom
// labels union. Returns nil rather than an empty map when there are no labels.
func (t *Tracer) goCustomLabels(src *support.CustomLabelsArray) map[libpf.String]libpf.String {
	// get_go_custom_labels sets the tag even for an empty label slice.
	n := int(src.Len)
	if n == 0 {
		return nil
	}
	labels := make(map[libpf.String]libpf.String, n)
	for _, lbl := range src.Labels[:n] {
		keyBytes, ok := t.customLabels.validateKey(lbl.Key[:])
		if !ok {
			log.Debugf("Dropping Go custom label with empty or invalid UTF-8 name")
			continue
		}
		key := libpf.Intern(pfunsafe.ToString(keyBytes))
		valBytes, ok := t.customLabels.validateValue(lbl.Val[:])
		if !ok {
			log.Debugf("Dropping Go custom label %s with invalid UTF-8 value", key)
			continue
		}
		labels[key] = libpf.Intern(pfunsafe.ToString(valBytes))
	}
	return labels
}

// threadContextCustomLabels decodes the opaque variant of the Trace custom
// labels union against the schema pid published.
func (t *Tracer) threadContextCustomLabels(payload *support.CustomLabelsData,
	pid libpf.PID) map[libpf.String]libpf.String {
	size := int(payload.Size)
	if size > len(payload.Data) {
		// Not a publisher fault: the eBPF producer must clamp this, so exceeding
		// it means the eBPF and user-space layouts disagree and nothing in the
		// payload can be trusted.
		log.Warnf("Thread context payload size %d exceeds the %d byte buffer "+
			"(PID %d): eBPF and user-space layouts disagree, dropping labels",
			size, len(payload.Data), pid)
		return nil
	}
	if size == 0 {
		// The common case: a process publishing only trace/span IDs sends no
		// attributes, so skip the decoder lookup and its lock.
		return nil
	}
	// Key indices mean nothing without the published schema. A PID with none
	// can be permanent (no publisher, or an unsupported schema version) rather
	// than a startup race, so count instead of logging.
	dec := t.processManager.LabelDecoderForPID(pid)
	if dec == nil {
		t.threadContextLabels.droppedSamplesNoSchema.Add(1)
		return nil
	}
	labels, dropped := dec.DecodeLabels(payload.Data[:size])
	if dropped > 0 {
		t.threadContextLabels.droppedEntriesUndecodable.Add(int64(dropped))
	}
	return labels
}
