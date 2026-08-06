// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestResourceToContextKey(t *testing.T) {
	tests := []struct {
		name     string
		attrs    map[string]string
		nilRes   bool
		expected string
	}{
		{name: "nil resource", nilRes: true, expected: ""},
		{name: "empty resource", expected: ""},
		{
			name: "all three present",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.name":        "svc",
				"service.instance.id": "id",
			},
			expected: "ns:svc:id",
		},
		{
			name: "missing namespace",
			attrs: map[string]string{
				"service.name":        "svc",
				"service.instance.id": "id",
			},
			expected: ":svc:id",
		},
		{
			name: "missing name",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.instance.id": "id",
			},
			expected: "ns::id",
		},
		{
			name: "missing instance id",
			attrs: map[string]string{
				"service.namespace": "ns",
				"service.name":      "svc",
			},
			expected: "ns:svc:",
		},
		{
			name: "irrelevant attributes ignored",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.name":        "svc",
				"service.instance.id": "id",
				"deployment.env":      "prod",
			},
			expected: "ns:svc:id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resource *pcommon.Resource
			if !tt.nilRes {
				r := pcommon.NewResource()
				for key, value := range tt.attrs {
					r.Attributes().PutStr(key, value)
				}
				resource = &r
			}
			assert.Equal(t, tt.expected, resourceToContextKey(resource).String())
		})
	}
}
