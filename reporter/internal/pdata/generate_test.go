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

func TestAddProfileAttributes(t *testing.T) {
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

func TestGetStringMapIndex(t *testing.T) {
	for _, tt := range []struct {
		name      string
		stringMap map[string]int32
		value     string

		wantStringMap map[string]int32
		wantIndex     int32
	}{
		{
			name:      "with a value not yet in the string map",
			stringMap: map[string]int32{},
			value:     "test",

			wantIndex:     0,
			wantStringMap: map[string]int32{"test": 0},
		},
		{
			name:      "with a value already in the string map",
			stringMap: map[string]int32{"test": 42},
			value:     "test",

			wantIndex:     42,
			wantStringMap: map[string]int32{"test": 42},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stringMap := tt.stringMap

			i := getStringMapIndex(stringMap, tt.value)
			assert.Equal(t, tt.wantIndex, i)
			assert.Equal(t, tt.wantStringMap, stringMap)
		})
	}
}

func TestCreateFunctionEntry(t *testing.T) {
	for _, tt := range []struct {
		name     string
		funcMap  map[samples.FuncInfo]int32
		funcName string
		fileName string

		wantIndex   int32
		wantFuncMap map[samples.FuncInfo]int32
	}{
		{
			name:     "with ane entry not yet in the func map",
			funcMap:  map[samples.FuncInfo]int32{},
			funcName: "my_method",
			fileName: "/tmp",

			wantIndex: 0,
			wantFuncMap: map[samples.FuncInfo]int32{
				{Name: "my_method", FileName: "/tmp"}: 0,
			},
		},
		{
			name: "with ane entry already in the func map",
			funcMap: map[samples.FuncInfo]int32{
				{Name: "my_method", FileName: "/tmp"}: 42,
			},
			funcName: "my_method",
			fileName: "/tmp",

			wantIndex: 42,
			wantFuncMap: map[samples.FuncInfo]int32{
				{Name: "my_method", FileName: "/tmp"}: 42,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			funcMap := tt.funcMap

			i := createFunctionEntry(funcMap, tt.funcName, tt.fileName)
			assert.Equal(t, tt.wantIndex, i)
			assert.Equal(t, tt.wantFuncMap, funcMap)
		})
	}
}

func TestGetDummyMappingIndex(t *testing.T) {
	for _, tt := range []struct {
		name            string
		fileIDToMapping map[libpf.FileID]int32
		stringMap       map[string]int32
		attributeMap    map[string]int32
		fileID          libpf.FileID

		wantIndex           int32
		wantFileIDToMapping map[libpf.FileID]int32
		wantMappingTable    []int32
		wantStringMap       map[string]int32
		wantAttributeMap    map[string]int32
	}{
		{
			name: "with an index already in the file id mapping",
			fileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 42,
			},
			fileID: libpf.UnsymbolizedFileID,

			wantIndex: 42,
		},
		{
			name:            "with an index not yet in the file id mapping",
			fileIDToMapping: map[libpf.FileID]int32{},
			stringMap:       map[string]int32{},
			attributeMap:    map[string]int32{},
			fileID:          libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantFileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{0},
			wantStringMap:    map[string]int32{"": 0},
			wantAttributeMap: map[string]int32{
				"process.executable.build_id.htlhash_ffffffffffffffffffffffffffffffff": 0,
			},
		},
		{
			name: "with an index not yet in the file id mapping and a filename in the string table",

			fileIDToMapping: map[libpf.FileID]int32{},
			stringMap:       map[string]int32{"": 42},
			attributeMap:    map[string]int32{},
			fileID:          libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantFileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{42},
			wantStringMap:    map[string]int32{"": 42},
			wantAttributeMap: map[string]int32{
				"process.executable.build_id.htlhash_ffffffffffffffffffffffffffffffff": 0,
			},
		},
		{
			name: "with an index not yet in the file id mapping and an attribute in the map",

			fileIDToMapping: map[libpf.FileID]int32{},
			stringMap:       map[string]int32{},
			attributeMap: map[string]int32{
				"process.executable.build_id.htlhash_ffffffffffffffffffffffffffffffff": 42,
			},
			fileID: libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantFileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{0},
			wantStringMap:    map[string]int32{"": 0},
			wantAttributeMap: map[string]int32{
				"process.executable.build_id.htlhash_ffffffffffffffffffffffffffffffff": 42,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fitm := tt.fileIDToMapping
			stringMap := tt.stringMap
			attributeMap := tt.attributeMap
			profile := pprofile.NewProfile()

			i := getDummyMappingIndex(fitm, stringMap, attributeMap, profile, tt.fileID)
			assert.Equal(t, tt.wantIndex, i)
			assert.Equal(t, tt.fileIDToMapping, fitm)
			assert.Equal(t, tt.wantStringMap, stringMap)
			assert.Equal(t, tt.wantAttributeMap, attributeMap)

			require.Equal(t, len(tt.wantMappingTable), profile.MappingTable().Len())
			for i, v := range tt.wantMappingTable {
				mapp := profile.MappingTable().At(i)
				assert.Equal(t, v, mapp.FilenameStrindex())
			}
		})
	}
}
