package pdata

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

func TestGetSampleAttributes(t *testing.T) {
	tests := map[string]struct {
		profile                pprofile.Profile
		k                      []samples.TraceAndMetaKey
		attributeMap           map[string]uint64
		expectedIndices        [][]uint64
		expectedAttributeTable map[string]any
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
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0}},
			expectedAttributeTable: map[string]any{
				"process.pid": 0,
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
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2, 3}, {0, 1, 2, 3}},
			expectedAttributeTable: map[string]any{
				"container.id": "containerID1",
				"thread.name":  "comm1",
				"service.name": "apmServiceName1",
				"process.pid":  1234,
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
			attributeMap:    make(map[string]uint64),
			expectedIndices: [][]uint64{{0, 1, 2, 3}, {4, 5, 6, 7}},
			expectedAttributeTable: map[string]any{
				"container.id": "containerID1",
				"thread.name":  "comm1",
				"service.name": "apmServiceName1",
				"process.pid":  1234,
			},
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			indices := make([][]uint64, 0)
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
			require.Equal(t, tc.expectedIndices, indices)

			wantAt := pcommon.NewMap()
			require.NoError(t, wantAt.FromRaw(tc.expectedAttributeTable))
			require.Equal(t, wantAt, tc.profile.AttributeTable())
		})
	}
}
