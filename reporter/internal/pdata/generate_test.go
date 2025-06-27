package pdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"

	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestGetDummyMappingIndex(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mappingSet OrderedSet[libpf.FileID]
		stringSet  OrderedSet[string]
		fileID     libpf.FileID

		wantIndex        int32
		wantMappingSet   OrderedSet[libpf.FileID]
		wantMappingTable []int32
		wantStringSet    OrderedSet[string]
	}{
		{
			name: "with an index already in the file id mapping",
			mappingSet: OrderedSet[libpf.FileID]{
				libpf.UnsymbolizedFileID: 42,
			},
			fileID:    libpf.UnsymbolizedFileID,
			wantIndex: 42,
			wantMappingSet: OrderedSet[libpf.FileID]{
				libpf.UnsymbolizedFileID: 42,
			},
		},
		{
			name:       "with an index not yet in the file id mapping",
			mappingSet: OrderedSet[libpf.FileID]{},
			stringSet:  OrderedSet[string]{},
			fileID:     libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantMappingSet: OrderedSet[libpf.FileID]{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{0},
			wantStringSet:    OrderedSet[string]{"": 0},
		},
		{
			name: "with an index not yet in the file id mapping and a filename in the string table",

			mappingSet: OrderedSet[libpf.FileID]{},
			stringSet:  OrderedSet[string]{"": 42},
			fileID:     libpf.UnsymbolizedFileID,

			wantIndex: 0,
			wantMappingSet: OrderedSet[libpf.FileID]{
				libpf.UnsymbolizedFileID: 0,
			},
			wantMappingTable: []int32{42},
			wantStringSet:    OrderedSet[string]{"": 42},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mappingSet := tt.mappingSet
			stringSet := tt.stringSet
			dic := pprofile.NewProfilesDictionary()
			mgr := samples.NewAttrTableManager(dic.AttributeTable())

			idx, exists := mappingSet.AddWithCheck(tt.fileID)
			if !exists {
				mapping := dic.MappingTable().AppendEmpty()
				mapping.SetFilenameStrindex(stringSet.Add(""))
				mgr.AppendOptionalString(mapping.AttributeIndices(),
					semconv.ProcessExecutableBuildIDHtlhashKey,
					tt.fileID.StringNoQuotes())
			}

			assert.Equal(t, tt.wantIndex, idx)
			assert.Equal(t, tt.wantMappingSet, mappingSet)
			assert.Equal(t, tt.wantStringSet, stringSet)

			require.Equal(t, len(tt.wantMappingTable), dic.MappingTable().Len())
			for i, v := range tt.wantMappingTable {
				mapp := dic.MappingTable().At(i)
				assert.Equal(t, v, mapp.FilenameStrindex())
			}
		})
	}
}

//nolint:lll
func TestFunctionTableOrder(t *testing.T) {
	for _, tt := range []struct {
		name        string
		executables map[libpf.FileID]samples.ExecInfo
		frames      map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo
		events      map[libpf.Origin]samples.KeyToEventMapping

		wantFunctionTable        []string
		expectedResourceProfiles int
	}{
		{
			name:                     "no events",
			executables:              map[libpf.FileID]samples.ExecInfo{},
			frames:                   map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo{},
			events:                   map[libpf.Origin]samples.KeyToEventMapping{},
			wantFunctionTable:        []string{""},
			expectedResourceProfiles: 0,
		}, {
			name:                     "single executable",
			expectedResourceProfiles: 1,
			executables: map[libpf.FileID]samples.ExecInfo{
				libpf.NewFileID(2, 3): {},
			},
			frames: map[libpf.FileID]map[libpf.AddressOrLineno]samples.SourceInfo{
				libpf.NewFileID(2, 3): {
					libpf.AddressOrLineno(0xef):  {FunctionName: libpf.Intern("func1")},
					libpf.AddressOrLineno(0x1ef): {FunctionName: libpf.Intern("func2")},
					libpf.AddressOrLineno(0x2ef): {FunctionName: libpf.Intern("func3")},
					libpf.AddressOrLineno(0x3ef): {FunctionName: libpf.Intern("func4")},
					libpf.AddressOrLineno(0x4ef): {FunctionName: libpf.Intern("func5")},
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
			for fileID, addrWithSourceInfos := range tt.frames {
				for addr, si := range addrWithSourceInfos {
					d.Frames.Add(libpf.NewFrameID(fileID, addr), si)
				}
			}
			for k, v := range tt.executables {
				d.Executables.Add(k, v)
			}
			tree := make(samples.TraceEventsTree)
			tree[""] = tt.events
			res, _ := d.Generate(tree, tt.name, "version")
			require.Equal(t, tt.expectedResourceProfiles, res.ResourceProfiles().Len())
			if tt.expectedResourceProfiles == 0 {
				// Do not check elements of ResourceProfile if there is no expected
				// ResourceProfile.
				return
			}
			require.Equal(t, 1, res.ResourceProfiles().At(0).ScopeProfiles().Len())
			expectedProfiles := len(tt.events)
			require.Equal(t, expectedProfiles, res.ResourceProfiles().
				At(0).ScopeProfiles().
				At(0).Profiles().Len())
			if expectedProfiles == 0 {
				return
			}
			dic := res.ProfilesDictionary()
			require.Equal(t, len(tt.wantFunctionTable), dic.FunctionTable().Len())
			for i := 0; i < dic.FunctionTable().Len(); i++ {
				funcName := dic.StringTable().At(int(dic.FunctionTable().At(i).NameStrindex()))
				assert.Equal(t, tt.wantFunctionTable[i], funcName)
			}
		})
	}
}

func TestProfileDuration(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events map[libpf.Origin]samples.KeyToEventMapping
	}{
		{
			name: "profile duration",
			events: map[libpf.Origin]samples.KeyToEventMapping{
				support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{Pid: 1}: {
						Timestamps: []uint64{2, 1, 3, 4, 7},
					},
					{Pid: 2}: {
						Timestamps: []uint64{8},
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(100, 100, 100, nil)
			require.NoError(t, err)

			tree := make(samples.TraceEventsTree)
			tree[""] = tt.events
			res, err := d.Generate(tree, tt.name, "version")
			require.NoError(t, err)

			profile := res.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0)
			require.Equal(t, pcommon.Timestamp(7), profile.Duration())
			require.Equal(t, pcommon.Timestamp(1), profile.StartTime())
		})
	}
}
