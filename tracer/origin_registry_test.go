// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			var r originRegistry
			id, err := r.Register(tc.metadata)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, r.lookup(1))
				return
			}
			require.NoError(t, err)
			assert.Same(t, tc.metadata, r.lookup(id))
		})
	}
}
