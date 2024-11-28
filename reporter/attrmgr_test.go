package reporter

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	common "go.opentelemetry.io/proto/otlp/common/v1"
)

func TestAttrTableManager(t *testing.T) {
	tests := map[string]struct {
		k                      []traceAndMetaKey
		expectedIndices        [][]uint64
		expectedAttributeTable []*common.KeyValue
	}{
		"empty": {
			k: []traceAndMetaKey{
				{
					hash:           libpf.TraceHash{},
					comm:           "",
					apmServiceName: "",
					containerID:    "",
					pid:            0,
				},
			},
			expectedIndices: [][]uint64{{0}},
			expectedAttributeTable: []*common.KeyValue{
				{
					Key: "process.pid",
					Value: &common.AnyValue{
						Value: &common.AnyValue_IntValue{IntValue: 0},
					},
				},
			},
		},
		"duplicate": {
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
		t.Run(name, func(t *testing.T) {
			attrTable := []*common.KeyValue{}
			mgr := NewAttrTableManager(&attrTable)
			indices := make([][]AttrIndex, 0)
			for _, k := range tc.k {
				indices = append(indices, []AttrIndex{
					mgr.AddStringAttr(semconv.ContainerIDKey, k.containerID),
					mgr.AddStringAttr(semconv.ThreadNameKey, k.comm),
					mgr.AddStringAttr(semconv.ServiceNameKey, k.apmServiceName),
					mgr.AddIntAttr(semconv.ProcessPIDKey, k.pid),
				})
			}
			require.Equal(t, tc.expectedIndices, indices)
			require.Equal(t, tc.expectedAttributeTable, attrTable)
		})
	}
}
