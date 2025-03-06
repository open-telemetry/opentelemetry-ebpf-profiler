package pdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
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

func TestFunctionTableOrder(t *testing.T) {
	for _, tt := range []struct {
		name        string
		executables map[libpf.FileID]samples.ExecInfo
		frames      map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo
		events      map[libpf.Origin]samples.KeyToEventMapping

		wantFunctionTable []string
	}{
		{
			name:              "with no executables",
			executables:       map[libpf.FileID]samples.ExecInfo{},
			frames:            map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo{},
			events:            map[libpf.Origin]samples.KeyToEventMapping{},
			wantFunctionTable: []string{""},
		}, {
			name: "single executable",
			executables: map[libpf.FileID]samples.ExecInfo{
				libpf.NewFileID(2, 3): {},
			},
			frames: map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo{
				libpf.NewFileID(2, 3): {
					libpf.AddressOrLineno(0xef):  {FunctionName: "func1"},
					libpf.AddressOrLineno(0x1ef): {FunctionName: "func2"},
					libpf.AddressOrLineno(0x2ef): {FunctionName: "func3"},
					libpf.AddressOrLineno(0x3ef): {FunctionName: "func4"},
					libpf.AddressOrLineno(0x4ef): {FunctionName: "func5"},
				},
			},
			events: map[libpf.Origin]samples.KeyToEventMapping{
				support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{}: {
						Files: []libpf.FileID{
							libpf.NewFileID(2, 3),
							libpf.NewFileID(2, 3),
							libpf.NewFileID(2, 3),
							libpf.NewFileID(2, 3),
							libpf.NewFileID(2, 3),
						},
						Linenos: []libpf.AddressOrLineno{
							libpf.AddressOrLineno(0xef),
							libpf.AddressOrLineno(0x1ef),
							libpf.AddressOrLineno(0x2ef),
							libpf.AddressOrLineno(0x3ef),
							libpf.AddressOrLineno(0x4ef),
						},
						FrameTypes: []libpf.FrameType{
							libpf.KernelFrame,
							libpf.KernelFrame,
							libpf.KernelFrame,
							libpf.KernelFrame,
							libpf.KernelFrame,
						},
						MappingStarts: []libpf.Address{
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
						},
						MappingEnds: []libpf.Address{
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
							libpf.Address(0),
						},
						MappingFileOffsets: []uint64{
							0,
							0,
							0,
							0,
							0,
						},
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
				},
			},
			wantFunctionTable: []string{
				"", "func1", "func2", "func3", "func4", "func5",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(100, 100, 100, nil)
			require.NoError(t, err)
			for k, v := range tt.frames {
				frames := xsync.NewRWMutex[map[libpf.AddressOrLineno]samples.SourceInfo](v)
				d.Frames.Add(k, &frames)
			}
			for k, v := range tt.executables {
				d.Executables.Add(k, v)
			}
			res := d.Generate(tt.events)
			expectedProfiles := len(tt.events)
			require.Equal(t, 1, res.ResourceProfiles().Len())
			require.Equal(t, 1, res.ResourceProfiles().At(0).ScopeProfiles().Len())
			require.Equal(t, expectedProfiles, res.ResourceProfiles().
				At(0).ScopeProfiles().
				At(0).Profiles().Len())
			if expectedProfiles == 0 {
				return
			}
			p := res.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0)
			require.Equal(t, len(tt.wantFunctionTable), p.FunctionTable().Len())
			for i := 0; i < p.FunctionTable().Len(); i++ {
				funcName := p.StringTable().At(int(p.FunctionTable().At(i).NameStrindex()))
				assert.Equal(t, tt.wantFunctionTable[i], funcName)
			}
		})
	}
}
