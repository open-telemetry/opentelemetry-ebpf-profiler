package reporter

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
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
					pid:            0,
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
					pid:            1234,
				},
				{
					hash:           libpf.TraceHash{},
					comm:           "comm1",
					apmServiceName: "apmServiceName1",
					containerID:    "containerID1",
					pid:            1234,
				},
			},
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2, 3}, {0, 1, 2, 3}},
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
					Key: "process.pid",
					Value: &common.AnyValue{
						Value: &common.AnyValue_IntValue{IntValue: 1234},
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
					pid:            1234,
				},
				{
					hash:           libpf.TraceHash{},
					comm:           "comm2",
					apmServiceName: "apmServiceName2",
					containerID:    "containerID2",
					pid:            6789,
				},
			},
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2, 3}, {4, 5, 6, 7}},
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
					Key: "process.pid",
					Value: &common.AnyValue{
						Value: &common.AnyValue_IntValue{IntValue: 1234},
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
				{
					Key: "process.pid",
					Value: &common.AnyValue{
						Value: &common.AnyValue_IntValue{IntValue: 6789},
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
				indices = append(indices, addProfileAttributes(tc.profile, []attrKeyValue{
					{key: string(semconv.ContainerIDKey), value: k.containerID},
					{key: string(semconv.ThreadNameKey), value: k.comm},
					{key: string(semconv.ServiceNameKey), value: k.apmServiceName},
					{key: string(semconv.ProcessPIDKey), value: k.pid},
				}, tc.attributeMap))
			}
			require.Equal(t, tc.expectedIndices, indices)
			require.Equal(t, tc.expectedAttributeTable, tc.profile.AttributeTable)
		})
	}
}
