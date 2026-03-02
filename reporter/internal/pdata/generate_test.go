package pdata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	v1profiles "go.opentelemetry.io/proto/otlp/profiles/v1development"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/sig-profiling/tools/profcheck"

	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// Test collection window: 60 second duration
	testCollectionStart = time.Unix(1000, 0)
	testCollectionEnd   = time.Unix(1060, 0)
	// Expected profile metadata based on collection window
	testProfileTime     = pcommon.Timestamp(testCollectionStart.UnixNano())
	testProfileDuration = uint64(testCollectionEnd.Sub(testCollectionStart).Nanoseconds())
)

// testGenerate is a helper that calls Generate with the standard test collection window
func testGenerate(p *Pdata, tree samples.TraceEventsTree, name, version string) (pprofile.Profiles, error) {
	return p.Generate(tree, name, version, testCollectionStart, testCollectionEnd)
}

func TestGetDummyMappingIndex(t *testing.T) {
	fileID := libpf.NewFileID(12345678, 12345678)
	for _, tt := range []struct {
		name       string
		mappingSet orderedset.OrderedSet[libpf.FileID]
		stringSet  orderedset.OrderedSet[string]
		fileID     libpf.FileID

		wantIndex        int32
		wantMappingSet   orderedset.OrderedSet[libpf.FileID]
		wantMappingTable []int32
		wantStringSet    orderedset.OrderedSet[string]
	}{
		{
			name: "with an index already in the file id mapping",
			mappingSet: orderedset.OrderedSet[libpf.FileID]{
				fileID: 42,
			},
			fileID:    fileID,
			wantIndex: 42,
			wantMappingSet: orderedset.OrderedSet[libpf.FileID]{
				fileID: 42,
			},
		},
		{
			name:       "with an index not yet in the file id mapping",
			mappingSet: orderedset.OrderedSet[libpf.FileID]{},
			stringSet:  orderedset.OrderedSet[string]{},
			fileID:     fileID,

			wantIndex: 0,
			wantMappingSet: orderedset.OrderedSet[libpf.FileID]{
				fileID: 0,
			},
			wantMappingTable: []int32{0},
			wantStringSet:    orderedset.OrderedSet[string]{"": 0, "process.executable.build_id.htlhash": 1},
		},
		{
			name: "with an index not yet in the file id mapping and a filename in the string table",

			mappingSet: orderedset.OrderedSet[libpf.FileID]{},
			stringSet:  orderedset.OrderedSet[string]{"": 42},
			fileID:     fileID,

			wantIndex: 0,
			wantMappingSet: orderedset.OrderedSet[libpf.FileID]{
				fileID: 0,
			},
			wantMappingTable: []int32{42},
			wantStringSet:    orderedset.OrderedSet[string]{"": 42, "process.executable.build_id.htlhash": 1},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mappingSet := tt.mappingSet
			stringSet := tt.stringSet
			dic := pprofile.NewProfilesDictionary()
			mgr := samples.NewAttrTableManager(stringSet, dic.AttributeTable())

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

func newTestFrames(extraFrame bool) libpf.Frames {
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID: libpf.NewFileID(2, 3),
		}),
	})
	frames := make(libpf.Frames, 0, 5)
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0xef,
		FunctionName:    libpf.Intern("func1"),
		Mapping:         mapping,
	})
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x1ef,
		FunctionName:    libpf.Intern("func2"),
		Mapping:         mapping,
	})
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x2ef,
		FunctionName:    libpf.Intern("func3"),
		Mapping:         mapping,
	})
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x3ef,
		FunctionName:    libpf.Intern("func4"),
		Mapping:         mapping,
	})
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x4ef,
		FunctionName:    libpf.Intern("func5"),
		Mapping:         mapping,
	})

	if extraFrame {
		frames.Append(&libpf.Frame{
			Type:            libpf.KernelFrame,
			AddressOrLineno: 0x5ef,
			FunctionName:    libpf.Intern("func6"),
			Mapping:         mapping,
		})
	}
	return frames
}

func TestFunctionTableOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events map[libpf.Origin]samples.KeyToEventMapping

		wantFunctionTable        []string
		expectedResourceProfiles int
	}{
		{
			name:                     "no events",
			events:                   map[libpf.Origin]samples.KeyToEventMapping{},
			wantFunctionTable:        []string{""},
			expectedResourceProfiles: 0,
		}, {
			name:                     "single executable",
			expectedResourceProfiles: 1,
			events: map[libpf.Origin]samples.KeyToEventMapping{
				support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{Pid: 1}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
					// Test Function deduplication
					{Pid: 2}: {
						Frames:     newTestFrames(true),
						Timestamps: []uint64{6, 7, 8, 9, 10, 11},
					},
				},
			},
			wantFunctionTable: []string{
				"", "func1", "func2", "func3", "func4", "func5", "func6",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(100, nil)
			require.NoError(t, err)
			tree := make(samples.TraceEventsTree)
			tree[libpf.NullString] = tt.events
			res, _ := testGenerate(d, tree, tt.name, "version")
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
			dic := res.Dictionary()
			require.Equal(t, len(tt.wantFunctionTable), dic.FunctionTable().Len())
			for i := 0; i < dic.FunctionTable().Len(); i++ {
				funcName := dic.StringTable().At(int(dic.FunctionTable().At(i).NameStrindex()))
				assert.Equal(t, tt.wantFunctionTable[i], funcName)
			}
		})
	}
}

func TestProfileDuration(t *testing.T) {
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID: libpf.NewFileID(1, 2),
		}),
	})

	for _, tt := range []struct {
		name             string
		tree             samples.TraceEventsTree
		expectedTime     pcommon.Timestamp
		expectedDuration uint64
	}{
		{
			name: "samples within collection window",
			tree: samples.TraceEventsTree{
				libpf.NullString: map[libpf.Origin]samples.KeyToEventMapping{
					support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
						{Pid: 1}: {
							// Timestamps within the collection window (1000-1060)
							Timestamps: []uint64{
								uint64(time.Unix(1010, 0).UnixNano()),
								uint64(time.Unix(1020, 0).UnixNano()),
								uint64(time.Unix(1030, 0).UnixNano()),
							},
						},
						{Pid: 2}: {
							Timestamps: []uint64{uint64(time.Unix(1040, 0).UnixNano())},
						},
					},
				},
			},
			expectedTime:     testProfileTime,
			expectedDuration: testProfileDuration,
		},
		{
			name: "adjusted start time for buffered samples",
			tree: samples.TraceEventsTree{
				libpf.NullString: map[libpf.Origin]samples.KeyToEventMapping{
					support.TraceOriginSampling: {
						{Pid: 1}: {
							Frames: newTestFrames(false),
							// Sample before collection start (990 vs 1000)
							Timestamps: []uint64{uint64(time.Unix(990, 0).UnixNano())},
						},
					},
				},
			},
			expectedTime:     pcommon.Timestamp(time.Unix(990, 0).UnixNano()),
			expectedDuration: uint64(testCollectionEnd.Sub(time.Unix(990, 0)).Nanoseconds()),
		},
		{
			name: "adjusted across multiple containers",
			tree: samples.TraceEventsTree{
				libpf.Intern("container1"): map[libpf.Origin]samples.KeyToEventMapping{
					support.TraceOriginSampling: {
						{Pid: 1}: {
							Frames: singleFrameTrace(libpf.GoFrame, mapping, 0x10, "func1", libpf.NullString, 1),
							// Oldest sample at 985
							Timestamps: []uint64{uint64(time.Unix(985, 0).UnixNano())},
						},
					},
				},
				libpf.Intern("container2"): map[libpf.Origin]samples.KeyToEventMapping{
					support.TraceOriginSampling: {
						{Pid: 2}: {
							Frames: singleFrameTrace(libpf.GoFrame, mapping, 0x20, "func2", libpf.NullString, 2),
							// Newer old sample at 995
							Timestamps: []uint64{uint64(time.Unix(995, 0).UnixNano())},
						},
					},
				},
			},
			expectedTime:     pcommon.Timestamp(time.Unix(985, 0).UnixNano()),
			expectedDuration: uint64(testCollectionEnd.Sub(time.Unix(985, 0)).Nanoseconds()),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(100, nil)
			require.NoError(t, err)

			res, err := testGenerate(d, tt.tree, tt.name, "version")
			require.NoError(t, err)

			for i := 0; i < res.ResourceProfiles().Len(); i++ {
				rp := res.ResourceProfiles().At(i)
				for j := 0; j < rp.ScopeProfiles().Len(); j++ {
					sp := rp.ScopeProfiles().At(j)
					for k := 0; k < sp.Profiles().Len(); k++ {
						profile := sp.Profiles().At(k)
						assert.Equal(t, tt.expectedTime, profile.Time())
						assert.Equal(t, tt.expectedDuration, profile.DurationNano())
					}
				}
			}
		})
	}
}

func TestGenerate_EmptyTree(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	tree := make(samples.TraceEventsTree)
	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	assert.Equal(t, 0, profiles.ResourceProfiles().Len())
}

func singleFrameTrace(ty libpf.FrameType, mapping libpf.FrameMapping,
	lineno libpf.AddressOrLineno, funcName string, sourceFile libpf.String,
	sourceLine libpf.SourceLineno,
) libpf.Frames {
	frames := make(libpf.Frames, 0, 1)
	frames.Append(&libpf.Frame{
		Type:            ty,
		AddressOrLineno: lineno,
		FunctionName:    libpf.Intern(funcName),
		SourceFile:      sourceFile,
		SourceLine:      sourceLine,
		Mapping:         mapping,
	})
	return frames
}

func TestGenerate_SingleContainerSingleOrigin(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	funcName := "main"
	filePath := libpf.Intern("/bin/test")
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(1, 2),
			FileName: filePath,
		}),
	})

	traceKey := samples.TraceAndMetaKey{
		ExecutablePath: filePath,
		Comm:           libpf.Intern("testproc"),
		Pid:            123,
		Tid:            456,
		ApmServiceName: "svc",
	}
	events := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.GoFrame, mapping,
					0x10, funcName, filePath, 42),
				Timestamps: []uint64{uint64(time.Unix(1010, 0).UnixNano())},
				EnvVars: map[libpf.String]libpf.String{
					libpf.Intern("FOO"): libpf.Intern("BAR"),
				},
			},
		},
	}
	tree := samples.TraceEventsTree{
		libpf.Intern("container1"): events,
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())
	rp := profiles.ResourceProfiles().At(0)
	val, _ := rp.Resource().Attributes().Get(string(semconv.ContainerIDKey))
	assert.Equal(t, "container1", val.Str())
	assert.Equal(t, semconv.SchemaURL, rp.SchemaUrl())
	require.Equal(t, 1, rp.ScopeProfiles().Len())
	sp := rp.ScopeProfiles().At(0)
	assert.Equal(t, "agent", sp.Scope().Name())
	assert.Equal(t, "v1", sp.Scope().Version())
	assert.Equal(t, semconv.SchemaURL, sp.SchemaUrl())
	require.Equal(t, 1, sp.Profiles().Len())
	prof := sp.Profiles().At(0)
	assert.Equal(t, testProfileTime, prof.Time())
	assert.Equal(t, testProfileDuration, prof.DurationNano())

	t.Run("Check environment variable attribute", func(t *testing.T) {
		foundFOOKey := false
		foundBarValue := false

		dic := profiles.Dictionary()
		for _, attr := range dic.AttributeTable().All() {
			key := dic.StringTable().At(int(attr.KeyStrindex()))
			value := attr.Value()
			// Check if this is an environment variable attribute
			if key == "process.environment_variable.FOO" {
				foundFOOKey = true
				if value.Type() == pcommon.ValueTypeStr && value.Str() == "BAR" {
					foundBarValue = true
				}
			}
		}
		assert.True(t, foundFOOKey,
			"Attribute 'process.environment_variable.FOO' should be in the attribute table")
		assert.True(t, foundBarValue,
			"Environment variable value 'bar' should be in the attribute table")
	})
}

func TestGenerate_MultipleOriginsAndContainers(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(5, 6),
			FileName: libpf.Intern("/bin/foo"),
		}),
	})
	exec := libpf.Intern("/bin/foo")
	traceKey := samples.TraceAndMetaKey{ExecutablePath: exec}
	frames := singleFrameTrace(libpf.PythonFrame, mapping, 0x20, "f", exec, 1)

	events1 := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames: frames,
				Timestamps: []uint64{
					uint64(time.Unix(1010, 0).UnixNano()),
					uint64(time.Unix(1020, 0).UnixNano()),
				},
			},
		},
		support.TraceOriginOffCPU: {
			traceKey: &samples.TraceEvents{
				Frames: frames,
				Timestamps: []uint64{
					uint64(time.Unix(1030, 0).UnixNano()),
					uint64(time.Unix(1040, 0).UnixNano()),
				},
				OffTimes: []int64{10, 20},
			},
		},
	}
	events2 := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames:     frames,
				Timestamps: []uint64{uint64(time.Unix(1050, 0).UnixNano())},
			},
		},
	}
	tree := samples.TraceEventsTree{
		libpf.Intern("c1"): events1,
		libpf.Intern("c2"): events2,
	}

	profiles, err := testGenerate(d, tree, "agent", "v2")
	require.NoError(t, err)
	require.Equal(t, 2, profiles.ResourceProfiles().Len())

	// Since map iteration order is not guaranteed, we need to check containers by their ID
	containerProfileCounts := make(map[string]int)
	for i := 0; i < profiles.ResourceProfiles().Len(); i++ {
		rp := profiles.ResourceProfiles().At(i)
		val, exists := rp.Resource().Attributes().Get(string(semconv.ContainerIDKey))
		require.True(t, exists)
		containerID := val.Str()
		sp := rp.ScopeProfiles().At(0)
		profileCount := sp.Profiles().Len()
		containerProfileCounts[containerID] = profileCount

		// All profiles should have the same duration and start time based on collection window
		for j := range profileCount {
			prof := sp.Profiles().At(j)
			assert.Equal(t, testProfileTime, prof.Time(),
				"profile %d in container %s", j, containerID)
			assert.Equal(t, testProfileDuration, prof.DurationNano(),
				"profile %d in container %s", j, containerID)
		}
	}

	// c1 has both origins, so 2 profiles
	assert.Equal(t, 2, containerProfileCounts["c1"])
	// c2 has only sampling, so 1 profile
	assert.Equal(t, 1, containerProfileCounts["c2"])
}

func TestGenerate_StringAndFunctionTablePopulation(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	funcName := "myfunc"
	filePath := libpf.Intern("/bin/bar")
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(7, 8),
			FileName: filePath,
		}),
	})

	traceKey := samples.TraceAndMetaKey{ExecutablePath: filePath}
	events := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.PythonFrame, mapping, 0x30,
					funcName, filePath, 123),
				Timestamps: []uint64{42},
			},
		},
	}
	tree := samples.TraceEventsTree{
		libpf.Intern("c"): events,
	}

	profiles, err := testGenerate(d, tree, "agent", "v3")
	require.NoError(t, err)
	dic := profiles.Dictionary()
	// The string table should contain "" as first element, then function name and file path
	strs := dic.StringTable().At(0)
	assert.Contains(t, strs, "")
	// Convert StringSlice to a Go slice for assertion
	var stringTableSlice []string
	for i := 0; i < dic.StringTable().Len(); i++ {
		stringTableSlice = append(stringTableSlice, dic.StringTable().At(i))
	}
	assert.Contains(t, stringTableSlice, funcName)
	assert.Contains(t, stringTableSlice, filePath.String())
	// The function table should have the function name and file path indices set
	require.Equal(t, 2, dic.FunctionTable().Len())
	fn := dic.FunctionTable().At(1)
	assert.Equal(t, funcName, dic.StringTable().At(int(fn.NameStrindex())))
	assert.Equal(t, filePath.String(), dic.StringTable().At(int(fn.FilenameStrindex())))
}

func singleFrameNative(mappingFile libpf.FrameMappingFile, lineno libpf.AddressOrLineno,
	mappingStart, mappingEnd libpf.Address, mappingFileOffset uint64,
) libpf.Frames {
	frames := make(libpf.Frames, 0, 1)
	frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: lineno,
		Mapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			Start:      mappingStart,
			End:        mappingEnd,
			FileOffset: mappingFileOffset,
			File:       mappingFile,
		}),
	})
	return frames
}

func TestGenerate_NativeFrame(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	filePath := libpf.Intern("/usr/lib/libexample.so")
	mappingFile := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
		FileID:   libpf.NewFileID(9, 10),
		FileName: filePath,
	})

	traceKey := samples.TraceAndMetaKey{
		ExecutablePath: filePath,
		Comm:           libpf.Intern("native_app"),
		Pid:            789,
		Tid:            1011,
	}
	events := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames: singleFrameNative(mappingFile, 0x1000, 0x1000, 0x2000, 0x100),
				Timestamps: []uint64{
					uint64(time.Unix(1010, 0).UnixNano()),
					uint64(time.Unix(1020, 0).UnixNano()),
					uint64(time.Unix(1030, 0).UnixNano()),
				},
			},
		},
	}
	tree := samples.TraceEventsTree{
		libpf.Intern("native_container"): events,
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())

	// Check resource profile attributes
	rp := profiles.ResourceProfiles().At(0)
	val, exists := rp.Resource().Attributes().Get(string(semconv.ContainerIDKey))
	require.True(t, exists)
	assert.Equal(t, "native_container", val.Str())

	// Check scope profile
	require.Equal(t, 1, rp.ScopeProfiles().Len())
	sp := rp.ScopeProfiles().At(0)
	assert.Equal(t, "agent", sp.Scope().Name())
	assert.Equal(t, "v1", sp.Scope().Version())

	// Check profile
	require.Equal(t, 1, sp.Profiles().Len())
	prof := sp.Profiles().At(0)
	assert.Equal(t, testProfileTime, prof.Time())
	assert.Equal(t, testProfileDuration, prof.DurationNano())

	// Verify profile contains one sample
	assert.Equal(t, 1, prof.Samples().Len())
	sample := prof.Samples().At(0)
	assert.Len(t, sample.Values().AsRaw(), 0)
	assert.Len(t, sample.TimestampsUnixNano().AsRaw(), 3)

	// Check that the mapping table contains our native frame mapping
	// (plus the dummy mapping at index 0)
	dic := profiles.Dictionary()
	assert.GreaterOrEqual(t, dic.MappingTable().Len(), 2,
		"Mapping table should have dummy mapping + native frame mapping")

	// Find the mapping for our native frame (not the dummy one at index 0)
	var nativeMapping pprofile.Mapping
	found := false
	for i := 1; i < dic.MappingTable().Len(); i++ { // Skip dummy mapping at index 0
		mapping := dic.MappingTable().At(i)
		if mapping.MemoryStart() == uint64(0x1000) {
			nativeMapping = mapping
			found = true
			break
		}
	}
	require.True(t, found, "Should find mapping for native frame")

	// Verify mapping details
	assert.Equal(t, uint64(0x1000), nativeMapping.MemoryStart())
	assert.Equal(t, uint64(0x2000), nativeMapping.MemoryLimit())
	assert.Equal(t, uint64(0x100), nativeMapping.FileOffset())

	// Verify the filename is correctly set in the mapping
	filenameStrIndex := nativeMapping.FilenameStrindex()
	filename := dic.StringTable().At(int(filenameStrIndex))
	assert.Equal(t, filePath.String(), filename)

	// For native frames, function information is not populated in the function table
	// since it's resolved by the backend. The function table should be empty.
	assert.Equal(t, 1, dic.FunctionTable().Len(),
		"Function table should be empty for native frames")
}

func TestStackTableOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events map[libpf.Origin]samples.KeyToEventMapping

		wantStackTable           [][]int32
		expectedLocationTableLen int
	}{
		{
			name: "single stack",
			events: map[libpf.Origin]samples.KeyToEventMapping{
				support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
				},
			},
			wantStackTable: [][]int32{
				nil, {1, 2, 3, 4, 5},
			},
			expectedLocationTableLen: 6,
		},
		{
			name: "multiple stacks",
			events: map[libpf.Origin]samples.KeyToEventMapping{
				support.TraceOriginSampling: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{Pid: 1}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
				},
				// This test relies on an implementation detail for ordering of results:
				// it assumes that support.TraceOriginSampling events are processed first
				support.TraceOriginOffCPU: map[samples.TraceAndMetaKey]*samples.TraceEvents{
					{Pid: 2}: {
						Frames:     newTestFrames(true),
						Timestamps: []uint64{7, 8, 9, 10, 11, 12},
					},
					{Pid: 3}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{13, 14, 15, 16, 17},
					},
				},
			},
			wantStackTable: [][]int32{
				nil,
				{1, 2, 3, 4, 5},
				{1, 2, 3, 4, 5, 6},
			},
			expectedLocationTableLen: 7,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(100, nil)
			require.NoError(t, err)
			tree := make(samples.TraceEventsTree)
			tree[libpf.NullString] = tt.events
			res, _ := testGenerate(d, tree, tt.name, "version")

			dic := res.Dictionary()

			require.Equal(t, tt.expectedLocationTableLen, dic.LocationTable().Len())
			require.Equal(t, len(tt.wantStackTable), dic.StackTable().Len())
			for i := 0; i < dic.StackTable().Len(); i++ {
				locationIndices := dic.StackTable().At(i).LocationIndices().AsRaw()
				assert.Equal(t, tt.wantStackTable[i], locationIndices)
			}
		})
	}
}

func TestGenerate_Validate(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	funcName := "myfunc"
	filePath := libpf.Intern("/bin/bar")
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(7, 8),
			FileName: filePath,
		}),
	})

	traceKey := samples.TraceAndMetaKey{ExecutablePath: filePath}
	events := map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginSampling: {
			traceKey: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.PythonFrame, mapping, 0x30,
					funcName, filePath, 123),
				Timestamps: []uint64{42},
			},
		},
	}
	tree := samples.TraceEventsTree{
		libpf.Intern("native_container"): events,
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)

	// We can not directly use ConformanceChecker on profiles,
	// so we first need to marshal and unmarshal the data
	// for the expected format.

	req := pprofileotlp.NewExportRequestFromProfiles(profiles)
	contents, err := req.MarshalProto()
	require.NoError(t, err)

	var data v1profiles.ProfilesData
	err = proto.Unmarshal(contents, &data)
	require.NoError(t, err)

	// Fix for protobuf unmarshaling for ConformanceChecker: The first attribute
	// table entry must have a nil Value,but protobuf unmarshaling creates a
	// non-nil but empty AnyValue. Explicitly set it to nil.
	if data.Dictionary != nil && len(data.Dictionary.AttributeTable) > 0 {
		firstAttr := data.Dictionary.AttributeTable[0]
		if firstAttr.KeyStrindex == 0 && firstAttr.UnitStrindex == 0 {
			firstAttr.Value = nil
		}
	}

	err = (profcheck.ConformanceChecker{
		CheckDictionaryDuplicates: true,
		CheckSampleTimestampShape: true}).Check(&data)
	require.NoError(t, err)
}
