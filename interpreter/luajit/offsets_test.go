// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
)

const (
	openrestyBase = "openresty/openresty"
)

func TestOffsets(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		suf  string
		fail bool
	}{
		{"1.13.6.2-alpine", "0", true},
		{"1.15.8.3-alpine", "0", false},
		{"1.17.8.2-alpine", "0", false},
		{"1.19.9.1-focal", "0", false},
		{"1.21.4.3-buster-fat", "0", false},
		{"1.21.4.3-alpine", "0", false},
		{"1.25.3.2-bullseye-fat", "ROLLING", false},
		{"1.25.3.2-alpine", "ROLLING", false},
		{"jammy", "ROLLING", false},
		{"alpine", "ROLLING", false},
	} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			tag, suffix := tc.tag, tc.suf
			libFile := "libluajit-5.1.so.2.1." + suffix
			t.Run(tag+"-"+platform, func(t *testing.T) {
				target, noarm := cacheLibrary(t, tag, platform, libFile)
				if noarm {
					t.Skip("old openresty doesn't have arm")
				}

				ef, err := pfelf.Open(target)
				require.NoError(t, err)

				// create stacktrace deltas to make sure we can find interp bounds
				// some ugliness so we can run arm and x86 unit tests on both platforms.
				intervals, param, err := extractStackDeltas(target, ef)
				require.NoError(t, err)

				interp, err := extractInterpreterBounds(intervals.Deltas, param)
				require.NoError(t, err)

				ljd := luajitData{}
				err = extractOffsets(ef, &ljd, interp)

				if tc.fail {
					//nolint:lll
					require.Error(t, err, "unexpected glref offset 8, only luajit with LJ_GC64 is supported")
					return
				}

				require.NoError(t, err)
				require.NotZero(t, ljd.currentLOffset)
				require.NotZero(t, ljd.g2Traces)
				require.NotZero(t, ljd.g2Dispatch)

				od := offsetData{}
				err = od.init(ef)
				require.NoError(t, err)

				// Test that our chicanery for finding traceinfo checks out on symbolized builds.
				if ti, err1 := od.lookupSymbol("lj_cf_jit_util_traceinfo"); err1 == nil {
					ti2, err2 := od.findTraceInfoFromLuaOpen()
					require.NoError(t, err2)
					require.Equal(t, ti.Address, ti2.Address)
				}

				// Ditto for lj_dispatch_update
				if du, err1 := od.lookupSymbol("lj_dispatch_update"); err1 == nil {
					du2, err2 := od.e.findLjDispatchUpdateAddr(od.luajitOpen, od.luajitOpenAddr)
					require.NoError(t, err2)
					require.Equal(t, uint64(du.Address), du2)
				}

				// TODO: strip binary and do it again.
			})
		}
	}
}

func cacheLibrary(t *testing.T, tag, platform, libFile string) (string, bool) {
	baseDir := "/tmp/offsets_artifacts/" + tag + "/" + platform
	target := baseDir + "/libluajit-5.1.so"

	if strings.HasPrefix(tag, "1.13") || strings.HasPrefix(tag, "1.15") {
		if platform == "linux/arm64" {
			return "", true
		}
	}

	if _, err := os.Stat(target); os.IsNotExist(err) {
		err = os.MkdirAll(baseDir, 0o755)
		require.NoError(t, err)
		getLibFromImage(t, openrestyBase+":"+tag, platform, libFile, target)
	}
	return target, false
}

func extractStackDeltas(target string, ef *pfelf.File) (sdtypes.IntervalData, int32, error) {
	var intervals sdtypes.IntervalData
	if err := elfunwindinfo.Extract(target, &intervals); err != nil {
		return intervals, 0, err
	}

	var param int32
	switch ef.Machine {
	case elf.EM_AARCH64:
		param = 208
	case elf.EM_X86_64:
		param = 80
	}
	return intervals, param, nil
}

func getLibFromImage(t *testing.T, name, platform, fullPath, target string) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	image, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:         name,
			ImagePlatform: platform,
		},
		Started: false,
	})
	require.NoError(t, err)

	rc, err := image.CopyFileFromContainer(ctx, "/usr/local/openresty/luajit/lib/"+fullPath)
	require.NoError(t, err)
	defer rc.Close()
	f, err := os.Create(target)
	require.NoError(t, err)

	_, err = io.Copy(f, rc)
	require.NoError(t, err)
}

func TestX86LuaClose(t *testing.T) {
	testdata := []struct {
		name          string
		glRefExpected uint64
		curLExpected  uint64
		code          []byte
	}{
		{
			name:          "size-optimized-register-zero",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0x41, 0x55, //                               pushq   %r13
				0x4c, 0x8d, 0x2d, 0x3f, 0xd4, 0xff, 0xff, // leaq    -0x2bc1(%rip), %r13
				0x41, 0x54, //                               pushq   %r12
				0x41, 0xbc, 0x0a, 0x00, 0x00, 0x00, //       movl    $0xa, %r12d
				0x55,                   //                   pushq   %rbp
				0x53,                   //                   pushq   %rbx
				0x51,                   //                   pushq   %rcx
				0x48, 0x8b, 0x5f, 0x10, //                   movq    0x10(%rdi), %rbx
				0x48, 0x8b, 0xab, 0xc8, 0x00, 0x00, 0x00, // movq    0xc8(%rbx), %rbp
				0x48, 0x89, 0xef, // movq    %rbp, %rdi
				0xe8, 0x6e, 0x17, 0x00, 0x00, // callq   0x175f0 <luaJIT_profile_stop>
				0x31, 0xf6, // xorl    %esi, %esi
				0x48, 0x89, 0xef, // movq    %rbp, %rdi
				0x48, 0x89, 0xb3, 0x58, 0x01, 0x00, 0x00, // movq    %rsi, 0x158(%rbx)
			},
		},
	}

	for _, test := range testdata {
		x := x86Extractor{}
		glref, curL, err := x.findOffsetsFromLuaClose(test.code)
		require.NoError(t, err)
		require.Equal(t, test.glRefExpected, glref)
		require.Equal(t, test.curLExpected, curL)
	}
}

// spot testing
func TestFiles(t *testing.T) {
	files, err := os.ReadDir("./testdata")
	require.NoError(t, err)
	for _, de := range files {
		target := "./testdata/" + de.Name()
		fi, err := os.Stat(target)
		if err != nil || fi.IsDir() {
			continue
		}
		ef, err := pfelf.Open(target)
		// Skip non-elf files
		if err != nil {
			continue
		}
		ljd := luajitData{}

		// create stacktrace deltas to make sure we can find interp bounds
		// some ugliness so we can run arm and x86 unit tests on both platforms.
		intervals, param, err := extractStackDeltas(target, ef)
		require.NoError(t, err)

		interp, err := extractInterpreterBounds(intervals.Deltas, param)
		require.NoError(t, err)

		err = extractOffsets(ef, &ljd, interp)
		require.NoError(t, err, de)
		require.NotZero(t, ljd.currentLOffset)
		require.NotZero(t, ljd.g2Traces)
		require.NotZero(t, ljd.g2Dispatch)

		od := offsetData{}
		err = od.init(ef)
		require.NoError(t, err)

		// Test that our chicanery for finding traceinfo checks out on symbolized builds.
		if ti, err1 := od.lookupSymbol("lj_cf_jit_util_traceinfo"); err1 == nil {
			ti2, err2 := od.findTraceInfoFromLuaOpen()
			require.NoError(t, err2)
			require.Equal(t, ti.Address, ti2.Address)
		}

		// Ditto for lj_dispatch_update
		if du, err1 := od.lookupSymbol("lj_dispatch_update"); err1 == nil {
			du2, err2 := od.e.findLjDispatchUpdateAddr(od.luajitOpen, od.luajitOpenAddr)
			require.NoError(t, err2)
			require.Equal(t, uint64(du.Address), du2)
		}

		t.Logf("%s: %+v, interp: %+v", target, ljd, interp)
	}
}

func TestStructure(t *testing.T) {
	for _, tc := range []struct {
		tag string
		suf string
	}{
		// Seems like alpine and ubuntu always have symbols, debian doesn't
		{"1.15.8.3-alpine", "0"},
		{"1.17.8.2-alpine", "0"},
		{"1.19.9.1-focal", "0"},
		{"1.21.4.3-alpine", "0"},
		{"1.25.3.2-alpine", "ROLLING"},
		{"jammy", "ROLLING"},
		{"alpine", "ROLLING"},
	} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			tag, suffix := tc.tag, tc.suf
			libFile := "libluajit-5.1.so.2.1." + suffix
			t.Run(tag+"-"+platform, func(t *testing.T) {
				target, noarm := cacheLibrary(t, tag, platform, libFile)
				if noarm {
					t.Skip("old openresty doesn't have arm")
				}

				ef, err := elf.Open(target)
				require.NoError(t, err)

				dwarfData, err := ef.DWARF()
				require.NoError(t, err)
				entryReader := dwarfData.Reader()

				for {
					entry, err := entryReader.Next()
					require.NoError(t, err)
					if entry == nil {
						break
					}
					if entry.Tag == dwarf.TagStructType {
						ty, err := dwarfData.Type(entry.Offset)
						require.NoError(t, err)
						if s, ok := ty.(*dwarf.StructType); ok {
							switch s.StructName {
							case "GCtrace":
								checkStruct(t, trace{}, s, tracePartOffset)
							case "GCproto":
								checkStruct(t, protoRaw{}, s, 8)
							case "jit_State":
								// TODO: we don't have offset as we rely on g2traces so not sure
								// how to test...
							}
						}
					}
				}
			})
		}
	}
}

func checkStruct(t *testing.T, typ any, s *dwarf.StructType, base uintptr) {
	rtyp := reflect.TypeOf(typ)
	did := 0
	for i := 0; i < rtyp.NumField(); i++ {
		f := rtyp.Field(i)
		if f.Name != "_" {
			for s.Field[did].Name != f.Name {
				did++
			}
			require.Equal(t, s.Field[did].ByteOffset, int64(f.Offset+base))
		}
	}
}
