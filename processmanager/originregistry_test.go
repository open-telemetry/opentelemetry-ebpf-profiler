// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestOriginRegistryRegisterValidates(t *testing.T) {
	appendTwo := func(dst []int64, _ *samples.TraceEventMeta) []int64 { return append(dst, 0, 0) }
	two := []samples.SampleType{{Type: "a", Unit: "count"}, {Type: "b", Unit: "count"}}

	tests := map[string]struct {
		metadata *samples.TypeMetadata
		wantErr  string
	}{
		"no sample types": {
			metadata: &samples.TypeMetadata{AppendValues: samples.AppendFirstContextValue},
			wantErr:  "at least one sample type",
		},
		"without AppendValues": {
			metadata: &samples.TypeMetadata{SampleTypes: two[:1]},
			wantErr:  "needs AppendValues",
		},
		"one sample type": {
			metadata: &samples.TypeMetadata{
				SampleTypes:  two[:1],
				AppendValues: samples.AppendFirstContextValue,
			},
		},
		"several sample types": {
			metadata: &samples.TypeMetadata{SampleTypes: two, AppendValues: appendTwo},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var r OriginRegistry
			id, err := r.Register(&OriginEntry{Meta: tc.metadata})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, r.Lookup(1))
				return
			}
			require.NoError(t, err)
			entry := r.Lookup(id)
			assert.Same(t, tc.metadata, entry.Meta)
			assert.NotNil(t, entry.Hooks)
		})
	}
}

func TestOriginRegistryRegisterWithHooks(t *testing.T) {
	metadata := &samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: "a", Unit: "count"}},
		AppendValues: samples.AppendFirstContextValue,
	}
	hooks := &traceHandlerHooksStub{}

	var r OriginRegistry
	id, err := r.Register(&OriginEntry{Meta: metadata, Hooks: hooks})
	require.NoError(t, err)

	entry := r.Lookup(id)
	assert.Same(t, metadata, entry.Meta)
	assert.Same(t, hooks, entry.Hooks)
}

func TestOriginRegistryRegisterDefaultsHooks(t *testing.T) {
	metadata := &samples.TypeMetadata{
		SampleTypes:  []samples.SampleType{{Type: "a", Unit: "count"}},
		AppendValues: samples.AppendFirstContextValue,
	}

	var r OriginRegistry
	id, err := r.Register(&OriginEntry{Meta: metadata})
	require.NoError(t, err)

	entry := r.Lookup(id)
	assert.Same(t, metadata, entry.Meta)
	assert.Equal(t, StubTraceHandlerHooks{}, entry.Hooks)
}

type traceHandlerHooksStub struct{}

func (*traceHandlerHooksStub) PreHandleTrace(*TraceContext) bool { return true }

func (*traceHandlerHooksStub) PostHandleTrace(*TraceContext, *libpf.Trace) {}
