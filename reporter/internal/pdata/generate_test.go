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

	"github.com/open-telemetry/sig-profiling/profcheck"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"

	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

var (
	// Test collection window: 60 second duration
	testCollectionStart = time.Unix(1000, 0)
	testCollectionEnd   = time.Unix(1060, 0)
	// Expected profile metadata based on collection window
	testProfileTime     = pcommon.Timestamp(testCollectionStart.UnixNano())
	testProfileDuration = uint64(testCollectionEnd.Sub(testCollectionStart).Nanoseconds())
)

var (
	profileTypeSampling = &samples.TypeMetadata{
		PeriodType: "cpu",
		PeriodUnit: "nanoseconds",
		SampleType: "samples",
		SampleUnit: "count",
	}
	profileTypeOffCPU = &samples.TypeMetadata{
		SampleType:   "off_cpu",
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
	profileTypeHeapAlloc = &samples.TypeMetadata{
		SampleType:   "alloc_space",
		SampleUnit:   "bytes",
		ReportValues: true,
	}
)

// testGenerate is a helper that calls Generate with the standard test collection window
func testGenerate(p *Pdata, tree samples.TraceEventsTree, name, version string) (pprofile.Profiles, error) {
	return p.Generate(tree, name, version, testCollectionStart, testCollectionEnd, nil, nil)
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
		events map[*samples.TypeMetadata]samples.SampleToEvents

		wantFunctionTable        []string
		expectedResourceProfiles int
	}{
		{
			name:                     "no events",
			events:                   map[*samples.TypeMetadata]samples.SampleToEvents{},
			wantFunctionTable:        []string{""},
			expectedResourceProfiles: 0,
		}, {
			name:                     "single executable",
			expectedResourceProfiles: 1,
			events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeSampling: {
					{}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
					samples.SampleKey{Hash: libpf.NewTraceHash(0, 1)}: {
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
			if len(tt.events) > 0 {
				tree[samples.ResourceKey{PID: 1}] = samples.ResourceToProfiles{Events: tt.events}
			}
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
				samples.ResourceKey{PID: 1}: samples.ResourceToProfiles{Events: map[*samples.TypeMetadata]samples.SampleToEvents{
					profileTypeSampling: {
						{}: {
							// Timestamps within the collection window (1000-1060)
							Timestamps: []uint64{
								uint64(time.Unix(1010, 0).UnixNano()),
								uint64(time.Unix(1020, 0).UnixNano()),
								uint64(time.Unix(1030, 0).UnixNano()),
							},
						},
					},
				}},
				samples.ResourceKey{PID: 2}: samples.ResourceToProfiles{Events: map[*samples.TypeMetadata]samples.SampleToEvents{
					profileTypeSampling: {
						{}: {
							Timestamps: []uint64{uint64(time.Unix(1040, 0).UnixNano())},
						},
					},
				}},
			},
			expectedTime:     testProfileTime,
			expectedDuration: testProfileDuration,
		},
		{
			name: "adjusted start time for buffered samples",
			tree: samples.TraceEventsTree{
				samples.ResourceKey{PID: 1}: samples.ResourceToProfiles{Events: map[*samples.TypeMetadata]samples.SampleToEvents{
					profileTypeSampling: {
						{}: {
							Frames: newTestFrames(false),
							// Sample before collection start (990 vs 1000)
							Timestamps: []uint64{uint64(time.Unix(990, 0).UnixNano())},
						},
					},
				}},
			},
			expectedTime:     pcommon.Timestamp(time.Unix(990, 0).UnixNano()),
			expectedDuration: uint64(testCollectionEnd.Sub(time.Unix(990, 0)).Nanoseconds()),
		},
		{
			name: "adjusted across multiple containers",
			tree: samples.TraceEventsTree{
				samples.ResourceKey{PID: 1, ContainerID: libpf.Intern("container1")}: samples.ResourceToProfiles{Events: map[*samples.TypeMetadata]samples.SampleToEvents{
					profileTypeSampling: {
						{}: {
							Frames: singleFrameTrace(libpf.GoFrame, mapping, 0x10, "func1", libpf.NullString, 1),
							// Oldest sample at 985
							Timestamps: []uint64{uint64(time.Unix(985, 0).UnixNano())},
						},
					},
				}},
				samples.ResourceKey{PID: 2, ContainerID: libpf.Intern("container2")}: samples.ResourceToProfiles{Events: map[*samples.TypeMetadata]samples.SampleToEvents{
					profileTypeSampling: {
						{}: {
							Frames: singleFrameTrace(libpf.GoFrame, mapping, 0x20, "func2", libpf.NullString, 2),
							// Newer old sample at 995
							Timestamps: []uint64{uint64(time.Unix(995, 0).UnixNano())},
						},
					},
				}},
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

	resourceKey := samples.ResourceKey{
		ExecutablePath: filePath,
		PID:            123,
		APMServiceName: "svc",
		ContainerID:    libpf.Intern("container1"),
	}
	events := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{}: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.GoFrame, mapping,
					0x10, funcName, filePath, 42),
				Timestamps: []uint64{uint64(time.Unix(1010, 0).UnixNano())},
			},
		},
	}
	tree := samples.TraceEventsTree{
		resourceKey: samples.ResourceToProfiles{
			EnvVars: map[libpf.String]libpf.String{
				libpf.Intern("FOO"): libpf.Intern("BAR"),
			},
			Events: events,
		},
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
		rp := profiles.ResourceProfiles().At(0)
		val, exists := rp.Resource().Attributes().Get("process.environment_variable.FOO")
		assert.True(t, exists,
			"Attribute 'process.environment_variable.FOO' should be in the resource attributes")
		assert.Equal(t, "BAR", val.Str(),
			"Environment variable value 'BAR' should be in the resource attributes")
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
	frames := singleFrameTrace(libpf.PythonFrame, mapping, 0x20, "f", exec, 1)

	resourceKey1 := samples.ResourceKey{
		ExecutablePath: exec,
		ContainerID:    libpf.Intern("c1"),
	}
	events1 := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{}: &samples.TraceEvents{
				Frames: frames,
				Timestamps: []uint64{
					uint64(time.Unix(1010, 0).UnixNano()),
					uint64(time.Unix(1020, 0).UnixNano()),
				},
			},
		},
		profileTypeOffCPU: {
			{}: &samples.TraceEvents{
				Frames: frames,
				Timestamps: []uint64{
					uint64(time.Unix(1030, 0).UnixNano()),
					uint64(time.Unix(1040, 0).UnixNano()),
				},
				Values: []int64{10, 20},
			},
		},
	}
	resourceKey2 := samples.ResourceKey{
		ExecutablePath: exec,
		ContainerID:    libpf.Intern("c2"),
	}
	events2 := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{}: &samples.TraceEvents{
				Frames:     frames,
				Timestamps: []uint64{uint64(time.Unix(1050, 0).UnixNano())},
			},
		},
	}
	tree := samples.TraceEventsTree{
		resourceKey1: samples.ResourceToProfiles{Events: events1},
		resourceKey2: samples.ResourceToProfiles{Events: events2},
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

	resourceKey := samples.ResourceKey{
		ExecutablePath: filePath,
		ContainerID:    libpf.Intern("c"),
	}
	events := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{}: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.PythonFrame, mapping, 0x30,
					funcName, filePath, 123),
				Timestamps: []uint64{42},
			},
		},
	}
	tree := samples.TraceEventsTree{
		resourceKey: samples.ResourceToProfiles{Events: events},
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

	resourceKey := samples.ResourceKey{
		ExecutablePath: filePath,
		PID:            789,
		ContainerID:    libpf.Intern("native_container"),
	}
	events := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{
				Hash:   libpf.NewTraceHash(0, 1),
				Comm:   libpf.NewCommFromString("abc"),
				TID:    42,
				CPU:    73,
				SpanID: libpf.APMSpanID{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
				TraceID: libpf.APMTraceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
			}: &samples.TraceEvents{
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
		resourceKey: samples.ResourceToProfiles{Events: events},
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
	assert.Empty(t, sample.Values().AsRaw())
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

	// Verify SpanID and TraceID are set via Link
	linkIndex := sample.LinkIndex()
	assert.Positive(t, linkIndex, "Sample should have a link set (index > 0, since 0 is dummy)")
	link := dic.LinkTable().At(int(linkIndex))
	expectedSpanID := pcommon.SpanID{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}
	expectedTraceID := pcommon.TraceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27}
	assert.Equal(t, expectedSpanID, link.SpanID())
	assert.Equal(t, expectedTraceID, link.TraceID())

	// Verify Comm, TID, and CPU are set in sample attributes
	attributeIndices := sample.AttributeIndices().AsRaw()
	assert.NotEmpty(t, attributeIndices, "Sample should have attributes")

	attributeTable := dic.AttributeTable()
	stringTable := dic.StringTable()

	foundComm := false
	foundTID := false
	foundCPU := false

	for _, attrIdx := range attributeIndices {
		attr := attributeTable.At(int(attrIdx))
		keyStrIdx := attr.KeyStrindex()
		key := stringTable.At(int(keyStrIdx))

		switch key {
		case string(semconv.ThreadNameKey):
			assert.Equal(t, "abc", attr.Value().Str())
			foundComm = true
		case string(semconv.ThreadIDKey):
			assert.Equal(t, int64(42), attr.Value().Int())
			foundTID = true
		case string(semconv.CPULogicalNumberKey):
			assert.Equal(t, int64(73), attr.Value().Int())
			foundCPU = true
		}
	}

	assert.True(t, foundComm, "Sample should have Comm attribute set")
	assert.True(t, foundTID, "Sample should have TID attribute set")
	assert.True(t, foundCPU, "Sample should have CPU attribute set")
}

func TestStackTableOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events map[*samples.TypeMetadata]samples.SampleToEvents

		wantStackTable           [][]int32
		expectedLocationTableLen int
	}{
		{
			name: "single stack",
			events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeSampling: {
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
			events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeSampling: {
					{}: {
						Frames:     newTestFrames(false),
						Timestamps: []uint64{1, 2, 3, 4, 5},
					},
				},
				profileTypeOffCPU: {
					samples.SampleKey{Hash: libpf.NewTraceHash(0, 1)}: {
						Frames:     newTestFrames(true),
						Timestamps: []uint64{7, 8, 9, 10, 11, 12},
					},
					samples.SampleKey{Hash: libpf.NewTraceHash(0, 2)}: {
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
			tree[samples.ResourceKey{}] = samples.ResourceToProfiles{Events: tt.events}
			res, _ := testGenerate(d, tree, tt.name, "version")

			dic := res.Dictionary()

			require.Equal(t, tt.expectedLocationTableLen, dic.LocationTable().Len())
			require.Equal(t, len(tt.wantStackTable), dic.StackTable().Len())
			// Profile types are processed in a stable, but not caller-visible,
			// order, so compare stacks as a set rather than by index.
			var gotStackTable [][]int32
			for i := 0; i < dic.StackTable().Len(); i++ {
				gotStackTable = append(gotStackTable, dic.StackTable().At(i).LocationIndices().AsRaw())
			}
			assert.ElementsMatch(t, tt.wantStackTable, gotStackTable)
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

	resourceKey := samples.ResourceKey{
		ExecutablePath: filePath,
		ContainerID:    libpf.Intern("native_container"),
	}
	events := map[*samples.TypeMetadata]samples.SampleToEvents{
		profileTypeSampling: {
			{
				Hash:   libpf.NewTraceHash(0, 1),
				Comm:   libpf.NewCommFromString("abc"),
				TID:    42,
				CPU:    73,
				SpanID: libpf.APMSpanID{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
				TraceID: libpf.APMTraceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
			}: &samples.TraceEvents{
				Frames: singleFrameTrace(libpf.PythonFrame, mapping, 0x30,
					funcName, filePath, 123),
				Timestamps: []uint64{42},
			},
		},
	}
	tree := samples.TraceEventsTree{
		resourceKey: samples.ResourceToProfiles{Events: events},
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

	err = (profcheck.ConformanceChecker{
		CheckDictionaryDuplicates: true,
		CheckSampleTimestampShape: true}).Check(&data)
	require.NoError(t, err)
}

func singleEventTree(rk samples.ResourceKey, resourceAttrs attribute.Set) samples.TraceEventsTree {
	filePath := libpf.Intern("/bin/svc")
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(7, 8),
			FileName: filePath,
		}),
	})
	return samples.TraceEventsTree{
		rk: samples.ResourceToProfiles{
			ResourceAttrs: resourceAttrs,
			Events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeSampling: {
					{}: &samples.TraceEvents{
						Frames:     singleFrameTrace(libpf.NativeFrame, mapping, 0x10, "f", filePath, 1),
						Timestamps: []uint64{uint64(time.Unix(1010, 0).UnixNano())},
					},
				},
			},
		},
	}
}

func TestGenerate_ProcessContextResource(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	resourceAttrs := attribute.NewSet(
		attribute.String("service.namespace", "team-a"),
		attribute.String("service.instance.id", "instance-42"),
		attribute.String("deployment.environment", "prod"),
		attribute.Int("not-a-string", 7),
		semconv.ServiceName("proto-svc"),
		attribute.StringSlice("service.tags", []string{"tag1", "tag2"}),
		attribute.Slice("mixed.values", attribute.StringValue("s"), attribute.Int64Value(2)),
		attribute.Map("service.metadata",
			attribute.String("nested.key", "nested-value"),
			attribute.Int("nested.count", 7)),
		attribute.Bool("service.active", true),
		attribute.Float64("service.weight", 3.14),
		attribute.KeyValue{Key: "service.blob", Value: attribute.ByteSliceValue([]byte{1, 2, 3})},
		attribute.BoolSlice("service.flags", []bool{true, false}),
		attribute.Int64Slice("service.ports", []int64{80, 443}),
		attribute.Float64Slice("service.weights", []float64{1.5, 2.5}),
		attribute.Map("deep.map",
			attribute.KeyValue{Key: "slice", Value: attribute.SliceValue(
				attribute.StringValue("a"), attribute.Int64Value(1))},
			attribute.KeyValue{Key: "map", Value: attribute.MapValue(
				attribute.String("k", "v"))}),
		attribute.Slice("deep.slice",
			attribute.MapValue(attribute.String("k", "v")),
			attribute.SliceValue(attribute.StringValue("inner"))),
	)

	tree := singleEventTree(samples.ResourceKey{
		ExecutablePath: libpf.Intern("/bin/svc"),
		PID:            42,
	}, resourceAttrs)

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())
	attrs := profiles.ResourceProfiles().At(0).Resource().Attributes()

	expected := map[string]any{
		"service.namespace":            "team-a",
		"service.instance.id":          "instance-42",
		"deployment.environment":       "prod",
		"not-a-string":                 int64(7),
		string(semconv.ServiceNameKey): "proto-svc",
		"service.tags":                 []any{"tag1", "tag2"},
		"mixed.values":                 []any{"s", int64(2)},
		"service.metadata": map[string]any{
			"nested.key":   "nested-value",
			"nested.count": int64(7),
		},
		"service.active":  true,
		"service.weight":  3.14,
		"service.blob":    []byte{1, 2, 3},
		"service.flags":   []any{true, false},
		"service.ports":   []any{int64(80), int64(443)},
		"service.weights": []any{1.5, 2.5},
		"deep.map": map[string]any{
			"slice": []any{"a", int64(1)},
			"map":   map[string]any{"k": "v"},
		},
		"deep.slice": []any{
			map[string]any{"k": "v"},
			[]any{"inner"},
		},
		string(semconv.ProcessPIDKey):            int64(42),
		string(semconv.ProcessExecutablePathKey): "/bin/svc",
		string(semconv.ProcessExecutableNameKey): "svc",
	}
	assert.Equal(t, expected, attrs.AsRaw())
}

// EMPTY attribute values are valid OTLP and must reach the wire as empty
// pcommon values, at every nesting level, rather than being dropped.
func TestGenerate_ProcessContextResource_EmptyValues(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	tree := singleEventTree(samples.ResourceKey{
		ExecutablePath: libpf.Intern("/bin/svc"),
		PID:            42,
	}, attribute.NewSet(
		attribute.String("set", "v"),
		attribute.KeyValue{Key: "empty"},
		attribute.Slice("slice", attribute.StringValue("a"), attribute.Value{}),
		attribute.Map("map", attribute.String("kept", "v"), attribute.KeyValue{Key: "gone"}),
	))

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	attrs := profiles.ResourceProfiles().At(0).Resource().Attributes()

	expected := map[string]any{
		"set":                                    "v",
		"empty":                                  nil,
		"slice":                                  []any{"a", nil},
		"map":                                    map[string]any{"kept": "v", "gone": nil},
		string(semconv.ProcessPIDKey):            int64(42),
		string(semconv.ProcessExecutablePathKey): "/bin/svc",
		string(semconv.ProcessExecutableNameKey): "svc",
	}
	assert.Equal(t, expected, attrs.AsRaw())
}

func TestGenerate_ProcessContextResource_NoAttrs(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	tree := singleEventTree(samples.ResourceKey{
		ExecutablePath: libpf.Intern("/bin/svc"),
		PID:            99,
		APMServiceName: "apm-svc",
	}, attribute.Set{})

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())
	attrs := profiles.ResourceProfiles().At(0).Resource().Attributes()

	expected := map[string]any{
		string(semconv.ServiceNameKey):           "apm-svc",
		string(semconv.ProcessPIDKey):            int64(99),
		string(semconv.ProcessExecutablePathKey): "/bin/svc",
		string(semconv.ProcessExecutableNameKey): "svc",
	}
	assert.Equal(t, expected, attrs.AsRaw())
}

func TestHeapAllocProducesSpaceAndObjectsProfiles(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(11, 12),
			FileName: libpf.Intern("/bin/heap-app"),
		}),
	})
	frames := singleFrameTrace(libpf.NativeFrame, mapping, 0x1234, "", libpf.NullString, 0)

	timestamps := []uint64{
		uint64(time.Unix(1010, 0).UnixNano()),
		uint64(time.Unix(1020, 0).UnixNano()),
	}
	tree := samples.TraceEventsTree{
		{ExecutablePath: libpf.Intern("/bin/heap-app")}: samples.ResourceToProfiles{
			Events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeHeapAlloc: {
					{}: &samples.TraceEvents{
						Frames:     frames,
						Timestamps: timestamps,
						Values:     []int64{128, 256},
						AllocSizes: []int64{64, 128},
					},
				},
			},
		},
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())
	sp := profiles.ResourceProfiles().At(0).ScopeProfiles().At(0)
	require.Equal(t, 2, sp.Profiles().Len())

	profilesByType := make(map[string]pprofile.Profile)
	strings := profiles.Dictionary().StringTable()
	for i := 0; i < sp.Profiles().Len(); i++ {
		prof := sp.Profiles().At(i)
		sampleType := prof.SampleType()
		profilesByType[strings.At(int(sampleType.TypeStrindex()))] = prof
	}

	allocSpace, ok := profilesByType["alloc_space"]
	require.True(t, ok)
	assert.Equal(t, "bytes", strings.At(int(allocSpace.SampleType().UnitStrindex())))
	require.Equal(t, 1, allocSpace.Samples().Len())
	assert.Equal(t, []int64{128, 256}, allocSpace.Samples().At(0).Values().AsRaw())
	assert.Equal(t, timestamps, allocSpace.Samples().At(0).TimestampsUnixNano().AsRaw())

	allocObjects, ok := profilesByType["alloc_objects"]
	require.True(t, ok)
	assert.Equal(t, "count", strings.At(int(allocObjects.SampleType().UnitStrindex())))
	require.Equal(t, 1, allocObjects.Samples().Len())
	assert.Equal(t, []int64{2, 2}, allocObjects.Samples().At(0).Values().AsRaw())
	assert.Equal(t, timestamps, allocObjects.Samples().At(0).TimestampsUnixNano().AsRaw())
}

// TestHeapAllocObjectsUsesAllocSizeWeighting verifies that alloc_objects is
// derived from Values (byte-weight) divided by the per-event AllocSizes
// (raw allocation size), not a flat count of 1 per sample, and that a
// missing/zero size falls back to 1 rather than dividing by zero.
func TestHeapAllocObjectsUsesAllocSizeWeighting(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(11, 12),
			FileName: libpf.Intern("/bin/heap-app"),
		}),
	})
	frames := singleFrameTrace(libpf.NativeFrame, mapping, 0x1234, "", libpf.NullString, 0)

	timestamps := []uint64{
		uint64(time.Unix(1010, 0).UnixNano()),
		uint64(time.Unix(1020, 0).UnixNano()),
		uint64(time.Unix(1030, 0).UnixNano()),
	}
	tree := samples.TraceEventsTree{
		{ExecutablePath: libpf.Intern("/bin/heap-app")}: samples.ResourceToProfiles{
			Events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeHeapAlloc: {
					{}: &samples.TraceEvents{
						Frames:     frames,
						Timestamps: timestamps,
						// weight=1000 @ size=100 -> 10 objects.
						// weight=64 @ size=64 -> 1 object.
						// weight=500 @ size=0 (unknown) -> falls back to 1.
						Values:     []int64{1000, 64, 500},
						AllocSizes: []int64{100, 64, 0},
					},
				},
			},
		},
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)

	sp := profiles.ResourceProfiles().At(0).ScopeProfiles().At(0)
	strings := profiles.Dictionary().StringTable()
	var allocObjects pprofile.Profile
	for i := 0; i < sp.Profiles().Len(); i++ {
		prof := sp.Profiles().At(i)
		if strings.At(int(prof.SampleType().TypeStrindex())) == "alloc_objects" {
			allocObjects = prof
		}
	}
	require.Equal(t, 1, allocObjects.Samples().Len())
	assert.Equal(t, []int64{10, 1, 1}, allocObjects.Samples().At(0).Values().AsRaw())
}

// TestCompareSampleKeys exercises the sample-key comparator that gives the
// heap-alloc profiles their deterministic order: every field is a tiebreaker
// tier, and the comparator must be antisymmetric and only equal for equal keys.
func TestCompareSampleKeys(t *testing.T) {
	base := samples.SampleKey{
		Comm:    libpf.NewCommFromString("comm"),
		Hash:    libpf.NewTraceHash(1, 1),
		TID:     10,
		CPU:     20,
		SpanID:  libpf.APMSpanID{0x1},
		TraceID: libpf.APMTraceID{0x1},
	}
	with := func(mut func(*samples.SampleKey)) samples.SampleKey {
		k := base
		mut(&k)
		return k
	}

	// Equal keys compare equal.
	assert.Equal(t, 0, compareSampleKeys(base, base))

	// A difference in any single field yields a non-zero, antisymmetric result.
	for _, f := range []struct {
		name  string
		other samples.SampleKey
	}{
		{"comm", with(func(k *samples.SampleKey) { k.Comm = libpf.NewCommFromString("zzz") })},
		{"hash", with(func(k *samples.SampleKey) { k.Hash = libpf.NewTraceHash(1, 2) })},
		{"tid", with(func(k *samples.SampleKey) { k.TID = 11 })},
		{"cpu", with(func(k *samples.SampleKey) { k.CPU = 21 })},
		{"spanID", with(func(k *samples.SampleKey) { k.SpanID = libpf.APMSpanID{0x2} })},
		{"traceID", with(func(k *samples.SampleKey) { k.TraceID = libpf.APMTraceID{0x2} })},
		{"extraMeta", with(func(k *samples.SampleKey) { k.ExtraMeta = "x" })},
	} {
		t.Run(f.name, func(t *testing.T) {
			fwd := compareSampleKeys(base, f.other)
			rev := compareSampleKeys(f.other, base)
			assert.NotZero(t, fwd, "keys differing in %s must not compare equal", f.name)
			assert.Equal(t, fwd, -rev, "comparator must be antisymmetric for %s", f.name)
		})
	}
}

// TestSampleKeys_SortedDeterministic verifies that sampleKeys(_, true) returns a
// stable, fully-ordered sequence (independent of Go's randomized map iteration),
// and that sampleKeys(_, false) still returns the full set. This guards the
// sort that keeps the paired alloc profiles aligned — removing it would make the
// sorted call non-deterministic and fail here.
func TestSampleKeys_SortedDeterministic(t *testing.T) {
	events := samples.SampleToEvents{}
	for i := range 16 {
		events[samples.SampleKey{Hash: libpf.NewTraceHash(0, uint64(i+1)), TID: int64(i)}] =
			&samples.TraceEvents{}
	}

	first := sampleKeys(events, true)
	for range 5 {
		assert.Equal(t, first, sampleKeys(events, true),
			"sorted sampleKeys must be deterministic across calls")
	}
	for i := 1; i < len(first); i++ {
		assert.LessOrEqual(t, compareSampleKeys(first[i-1], first[i]), 0,
			"sorted sampleKeys must be in compareSampleKeys order")
	}

	assert.Len(t, sampleKeys(events, false), len(events),
		"unsorted sampleKeys must still return every key")
}

// TestGenerate_HeapAllocProfilesAligned verifies the invariant the heap-alloc
// sort exists to protect: alloc_space and alloc_objects are emitted as two
// separate Profile messages over the same events map, and their samples must
// line up index-for-index. With many distinct-stack keys, an unsorted (random)
// map iteration would almost certainly misalign the two profiles.
func TestGenerate_HeapAllocProfilesAligned(t *testing.T) {
	d, err := New(100, nil)
	require.NoError(t, err)

	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   libpf.NewFileID(11, 12),
			FileName: libpf.Intern("/bin/heap-app"),
		}),
	})

	const n = 64
	allocEvents := samples.SampleToEvents{}
	for i := range n {
		key := samples.SampleKey{
			Comm: libpf.NewCommFromString("comm"),
			Hash: libpf.NewTraceHash(uint64(i), uint64(i+1)),
			TID:  int64(i),
		}
		allocEvents[key] = &samples.TraceEvents{
			// Distinct address per key => distinct location => distinct stack,
			// so the stack-index sequence is a fingerprint of iteration order.
			Frames: singleFrameTrace(libpf.NativeFrame, mapping,
				libpf.AddressOrLineno(0x1000+i*0x10), "", libpf.NullString, 0),
			Timestamps: []uint64{uint64(testCollectionEnd.UnixNano())},
			Values:     []int64{int64((i + 1) * 100)},
			AllocSizes: []int64{int64((i + 1) * 10)},
		}
	}

	tree := samples.TraceEventsTree{
		{ExecutablePath: libpf.Intern("/bin/heap-app")}: samples.ResourceToProfiles{
			Events: map[*samples.TypeMetadata]samples.SampleToEvents{
				profileTypeHeapAlloc: allocEvents,
			},
		},
	}

	profiles, err := testGenerate(d, tree, "agent", "v1")
	require.NoError(t, err)
	require.Equal(t, 1, profiles.ResourceProfiles().Len())
	sp := profiles.ResourceProfiles().At(0).ScopeProfiles().At(0)
	require.Equal(t, 2, sp.Profiles().Len(), "heap alloc emits alloc_space + alloc_objects")

	strings := profiles.Dictionary().StringTable()
	stacksByType := make(map[string][]int32)
	for i := 0; i < sp.Profiles().Len(); i++ {
		prof := sp.Profiles().At(i)
		name := strings.At(int(prof.SampleType().TypeStrindex()))
		require.Equal(t, n, prof.Samples().Len(), "%s should have one sample per key", name)
		seq := make([]int32, prof.Samples().Len())
		for j := 0; j < prof.Samples().Len(); j++ {
			seq[j] = prof.Samples().At(j).StackIndex()
		}
		stacksByType[name] = seq
	}

	require.Contains(t, stacksByType, "alloc_space")
	require.Contains(t, stacksByType, "alloc_objects")
	assert.Equal(t, stacksByType["alloc_space"], stacksByType["alloc_objects"],
		"paired alloc profiles must list samples in the same order to line up index-for-index")

	// Sanity: alignment is only meaningful because the stacks are distinct.
	distinct := make(map[int32]struct{}, n)
	for _, s := range stacksByType["alloc_space"] {
		distinct[s] = struct{}{}
	}
	assert.Len(t, distinct, n, "each key should map to a distinct stack")
}
