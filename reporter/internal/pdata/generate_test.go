package pdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

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
		fileID          libpf.FileID

		wantIndex           int32
		wantFileIDToMapping map[libpf.FileID]int32
		wantMappingTable    []int32
		wantStringMap       map[string]int32
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
			fileID:          libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantFileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{0},
			wantStringMap:    map[string]int32{"": 0},
		},
		{
			name: "with an index not yet in the file id mapping and a filename in the string table",

			fileIDToMapping: map[libpf.FileID]int32{},
			stringMap:       map[string]int32{"": 42},
			fileID:          libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantFileIDToMapping: map[libpf.FileID]int32{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{42},
			wantStringMap:    map[string]int32{"": 42},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fitm := tt.fileIDToMapping
			stringMap := tt.stringMap
			profile := pprofile.NewProfile()
			mgr := samples.NewAttrTableManager(profile.AttributeTable())

			i := getDummyMappingIndex(fitm, stringMap, mgr, profile, tt.fileID)
			assert.Equal(t, tt.wantIndex, i)
			assert.Equal(t, tt.fileIDToMapping, fitm)
			assert.Equal(t, tt.wantStringMap, stringMap)

			require.Equal(t, len(tt.wantMappingTable), profile.MappingTable().Len())
			for i, v := range tt.wantMappingTable {
				mapp := profile.MappingTable().At(i)
				assert.Equal(t, v, mapp.FilenameStrindex())
			}
		})
	}
}
