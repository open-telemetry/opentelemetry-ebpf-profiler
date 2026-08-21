// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procmeta

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// TestResourceFromEnvVars covers the base resource a process's environment
// declares, and the precedence an enricher contribution has over it.
func TestResourceFromEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		contributed map[string]string
		envVars     map[libpf.String]libpf.String
		expected    map[string]string
	}{
		{
			name: "no env vars, no contribution",
		},
		{
			name: "OTEL_SERVICE_NAME",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("my-service"),
			},
			expected: map[string]string{
				"service.name": "my-service",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES simple",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key1=value1,key2=value2"),
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES percent-encoded values",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key1=val%2Cwith%2Ccomma,key2=value2"),
			},
			expected: map[string]string{
				"key1": "val,with,comma",
				"key2": "value2",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES percent-encoded keys",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key%3D2=value2,key%2C3=value3"),
			},
			expected: map[string]string{
				"key=2": "value2",
				"key,3": "value3",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES invalid encoding in value discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad=%ZZ"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES invalid encoding in key discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad%ZZ=value2"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES missing equals discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,badpair"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES empty value",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern(""),
			},
			expected: nil,
		},
		{
			name:        "a contribution is not overridden by OTEL_SERVICE_NAME",
			contributed: map[string]string{"service.name": "test-service"},
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("env-service"),
			},
			expected: map[string]string{
				"service.name": "test-service",
			},
		},
		{
			name: "both env vars",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("my-svc"),
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("deployment.environment=prod"),
			},
			expected: map[string]string{
				"service.name":           "my-svc",
				"deployment.environment": "prod",
			},
		},
		{
			name: "OTEL_SERVICE_NAME wins over service.name in OTEL_RESOURCE_ATTRIBUTES",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("from-service-name"),
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("service.name=from-attrs"),
			},
			expected: map[string]string{
				"service.name": "from-service-name",
			},
		},
		{
			// Per OTel spec, duplicate keys within OTEL_RESOURCE_ATTRIBUTES
			// resolve last-writer-wins.
			name: "OTEL_RESOURCE_ATTRIBUTES duplicate keys: last writer wins",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k=first,k=second,k=third"),
			},
			expected: map[string]string{
				"k": "third",
			},
		},
		{
			// A contribution still beats OTEL_RESOURCE_ATTRIBUTES, so the
			// dedup-then-apply order is observable: even though "from-attrs-second"
			// wins the intra-attr dedup, "preset" wins overall.
			name:        "a contribution beats the OTEL_RESOURCE_ATTRIBUTES last writer",
			contributed: map[string]string{"k": "preset"},
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k=from-attrs-first,k=from-attrs-second"),
			},
			expected: map[string]string{
				"k": "preset",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := ResourceFromEnvVars(tt.envVars)

			var contribution *pcommon.Resource
			if tt.contributed != nil {
				contribution = resourceWith(tt.contributed)
			}

			merged := MergeResources(base, []*pcommon.Resource{contribution})

			if tt.expected == nil {
				assert.Nil(t, merged)
				return
			}

			require.NotNil(t, merged)
			got := make(map[string]string)
			merged.Attributes().Range(func(k string, v pcommon.Value) bool {
				got[k] = v.Str()
				return true
			})
			assert.Equal(t, tt.expected, got)
		})
	}
}
