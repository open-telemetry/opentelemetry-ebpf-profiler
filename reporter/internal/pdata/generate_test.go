package pdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

type attributeStruct struct {
	Key   string
	Value any
}

func TestGetSampleAttributes(t *testing.T) {
	tests := map[string]struct {
		profile                pprofile.Profile
		k                      []samples.TraceAndMetaKey
		attributeMap           map[string]int32
		expectedIndices        [][]int32
		expectedAttributeTable []attributeStruct
	}{
		"empty": {
			profile: pprofile.NewProfile(),
			k: []samples.TraceAndMetaKey{
				{
					Hash:           libpf.TraceHash{},
					Comm:           "",
					ApmServiceName: "",
					ContainerID:    "",
					Pid:            0,
				},
			},
			attributeMap:    make(map[string]int32),
			expectedIndices: [][]int32{{0}},
			expectedAttributeTable: []attributeStruct{
				{Key: "process.pid", Value: int64(0)},
			},
		},
		"duplicate": {
			profile: pprofile.NewProfile(),
			k: []samples.TraceAndMetaKey{
				{
					Hash:           libpf.TraceHash{},
					Comm:           "comm1",
					ApmServiceName: "apmServiceName1",
					ContainerID:    "containerID1",
					Pid:            1234,
				},
				{
					Hash:           libpf.TraceHash{},
					Comm:           "comm1",
					ApmServiceName: "apmServiceName1",
					ContainerID:    "containerID1",
					Pid:            1234,
				},
			},
			attributeMap:    make(map[string]int32),
			expectedIndices: [][]int32{{0, 1, 2, 3}, {0, 1, 2, 3}},
			expectedAttributeTable: []attributeStruct{
				{Key: "container.id", Value: "containerID1"},
				{Key: "thread.name", Value: "comm1"},
				{Key: "service.name", Value: "apmServiceName1"},
				{Key: "process.pid", Value: int64(1234)},
			},
		},
		"different": {
			profile: pprofile.NewProfile(),
			k: []samples.TraceAndMetaKey{
				{
					Hash:           libpf.TraceHash{},
					Comm:           "comm1",
					ApmServiceName: "apmServiceName1",
					ContainerID:    "containerID1",
					Pid:            1234,
				},
				{
					Hash:           libpf.TraceHash{},
					Comm:           "comm2",
					ApmServiceName: "apmServiceName2",
					ContainerID:    "containerID2",
					Pid:            6789,
				},
			},
			attributeMap:    make(map[string]int32),
			expectedIndices: [][]int32{{0, 1, 2, 3}, {4, 5, 6, 7}},
			expectedAttributeTable: []attributeStruct{
				{Key: "container.id", Value: "containerID1"},
				{Key: "thread.name", Value: "comm1"},
				{Key: "service.name", Value: "apmServiceName1"},
				{Key: "process.pid", Value: int64(1234)},
				{Key: "container.id", Value: "containerID2"},
				{Key: "thread.name", Value: "comm2"},
				{Key: "service.name", Value: "apmServiceName2"},
				{Key: "process.pid", Value: int64(6789)},
			},
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			indices := make([][]int32, 0)
			for _, k := range tc.k {
				indices = append(indices, append(addProfileAttributes(tc.profile,
					[]samples.AttrKeyValue[string]{
						{Key: string(semconv.ContainerIDKey), Value: k.ContainerID},
						{Key: string(semconv.ThreadNameKey), Value: k.Comm},
						{Key: string(semconv.ServiceNameKey), Value: k.ApmServiceName},
					}, tc.attributeMap),
					addProfileAttributes(tc.profile,
						[]samples.AttrKeyValue[int64]{
							{Key: string(semconv.ProcessPIDKey), Value: k.Pid},
						}, tc.attributeMap)...))
			}
			assert.Equal(t, tc.expectedIndices, indices)

			require.Equal(t, len(tc.expectedAttributeTable), tc.profile.AttributeTable().Len())
			for i, v := range tc.expectedAttributeTable {
				attr := tc.profile.AttributeTable().At(i)
				assert.Equal(t, v.Key, attr.Key())
				assert.Equal(t, v.Value, attr.Value().AsRaw())
			}
		})
	}
}
