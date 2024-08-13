package reporter

import (
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/stretchr/testify/require"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	profiles "go.opentelemetry.io/proto/otlp/profiles/v1experimental"
)

func TestGetSampleAttributes(t *testing.T) {
	tests := map[string]struct {
		profile                *profiles.Profile
		k                      []traceAndMetaKey
		attributeMap           map[string]uint64
		expectedIndices        [][]uint64
		expectedAttributeTable []*common.KeyValue
	}{
		"empty": {
			profile: &profiles.Profile{},
			k: []traceAndMetaKey{
				{
					hash:           libpf.TraceHash{},
					comm:           "",
					apmServiceName: "",
					containerID:    "",
				},
			},
			attributeMap:           make(map[string]uint64),
			expectedIndices:        [][]uint64{make([]uint64, 0, 4)},
			expectedAttributeTable: nil,
		},
		"duplicate": {
			profile: &profiles.Profile{},
			k: []traceAndMetaKey{
				{
					hash:           libpf.TraceHash{},
					comm:           "comm1",
					apmServiceName: "apmServiceName1",
					containerID:    "containerID1",
				},
				{
					hash:           libpf.TraceHash{},
					comm:           "comm1",
					apmServiceName: "apmServiceName1",
					containerID:    "containerID1",
				},
			},
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2}, {0, 1, 2}},
			expectedAttributeTable: []*common.KeyValue{
				{
					Key: "container.id",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "containerID1"},
					},
				},
				{
					Key: "thread.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "comm1"},
					},
				},
				{
					Key: "service.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "apmServiceName1"},
					},
				},
			},
		},
		"different": {
			profile: &profiles.Profile{},
			k: []traceAndMetaKey{
				{
					hash:           libpf.TraceHash{},
					comm:           "comm1",
					apmServiceName: "apmServiceName1",
					containerID:    "containerID1",
				},
				{
					hash:           libpf.TraceHash{},
					comm:           "comm2",
					apmServiceName: "apmServiceName2",
					containerID:    "containerID2",
				},
			},
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2}, {3, 4, 5}},
			expectedAttributeTable: []*common.KeyValue{
				{
					Key: "container.id",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "containerID1"},
					},
				},
				{
					Key: "thread.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "comm1"},
					},
				},
				{
					Key: "service.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "apmServiceName1"},
					},
				},
				{
					Key: "container.id",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "containerID2"},
					},
				},
				{
					Key: "thread.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "comm2"},
					},
				},
				{
					Key: "service.name",
					Value: &common.AnyValue{
						Value: &common.AnyValue_StringValue{StringValue: "apmServiceName2"},
					},
				},
			},
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			indices := make([][]uint64, 0)
			for _, k := range tc.k {
				indices = append(indices, getSampleAttributes(tc.profile, k, tc.attributeMap))
			}
			require.Equal(t, tc.expectedIndices, indices)
			require.Equal(t, tc.expectedAttributeTable, tc.profile.AttributeTable)
		})
	}
}
