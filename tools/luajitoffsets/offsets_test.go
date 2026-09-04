// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build luajit_offsets_test

// Tests that extract offsets from real LuaJIT binaries. They pull
// openresty/openresty images through testcontainers, so they need Docker.
// The instruction-decoding tests that need no binaries stay in the main
// module, in interpreter/luajit/offsets_test.go.

package luajitoffsets

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"

	"go.opentelemetry.io/ebpf-profiler/interpreter/luajit"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	openrestyBase = "openresty/openresty"

	// lj_dispatch_update has no named constant in the luajit package because
	// scanSymbols does not look for it.
	ljDispatchUpdateSym libpf.SymbolName = "lj_dispatch_update"

	// protoRaw describes GCproto minus its first 8 bytes, the nextgc pointer.
	protoRawOffset = 8
)

func TestOffsets(t *testing.T) {
	// g2Dispatch is the offset from G to the value the LJ JIT loads into the
	// DISPATCH register (r14 on x86_64, r22 on aarch64). It's pinned per-build
	// because a wrong value silently sends bad-G candidates to the userland
	// triangulator and starves the eBPF JIT bootstrap path; only the rolling
	// alpine build has ever drifted, but every tag is asserted here so the
	// next time it does we catch it in CI rather than as flaky integration
	// tests.
	type expected struct {
		amd64G2Dispatch uint16
		arm64G2Dispatch uint16
	}
	for _, tc := range []struct {
		tag  string
		suf  string
		fail bool
		exp  expected
	}{
		{"1.13.6.2-alpine", "0", true, expected{}},
		{"1.15.8.3-alpine", "0", false, expected{amd64G2Dispatch: 0xf58}},
		{"1.17.8.2-alpine", "0", false, expected{amd64G2Dispatch: 0xf58, arm64G2Dispatch: 0xf38}},
		{"1.19.9.1-focal", "0", false, expected{amd64G2Dispatch: 0xfa0, arm64G2Dispatch: 0xf88}},
		{"1.21.4.3-buster-fat", "0", false, expected{amd64G2Dispatch: 0xfa8, arm64G2Dispatch: 0xf90}},
		{"1.21.4.3-alpine", "0", false, expected{amd64G2Dispatch: 0xfa8, arm64G2Dispatch: 0xf90}},
		{"1.25.3.2-bullseye-fat", "ROLLING", false, expected{amd64G2Dispatch: 0xfa8, arm64G2Dispatch: 0xf90}},
		{"1.25.3.2-alpine", "ROLLING", false, expected{amd64G2Dispatch: 0xfa8, arm64G2Dispatch: 0xf90}},
		{"jammy", "ROLLING", false, expected{amd64G2Dispatch: 0xfc8, arm64G2Dispatch: 0xfc0}},
		{"alpine", "ROLLING", false, expected{amd64G2Dispatch: 0xfc8, arm64G2Dispatch: 0xfc0}},
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

				interp, err := luajit.ExtractInterpreterBounds(ef.Machine, intervals, param)
				require.NoError(t, err)

				ljd, err := luajit.NewLuajitData(ef, interp)

				if tc.fail {
					//nolint:lll
					if platform == "linux/arm64" {
						require.ErrorContains(t, err, "unexpected glref offset 8, only luajit with LJ_GC64 is supported")
					} else {
						require.ErrorContains(t, err, "find offsets from lua_close failed")
					}
					return
				}

				require.NoError(t, err)
				require.NotZero(t, ljd.CurrentLOffset())
				require.NotZero(t, ljd.G2Traces())
				wantG2Dispatch := tc.exp.amd64G2Dispatch
				if platform == "linux/arm64" {
					wantG2Dispatch = tc.exp.arm64G2Dispatch
				}
				require.Equal(t, wantG2Dispatch, ljd.G2Dispatch(),
					"g2Dispatch mismatch: a wrong value here makes the eBPF JIT "+
						"bootstrap emit bad-G candidates and starves luajit "+
						"triangulation in CI")

				od, err := luajit.NewOffsetData(ef)
				require.NoError(t, err)

				// Test that our chicanery for finding traceinfo checks out on symbolized builds.
				if ti, ok := od.FoundSymbols()[luajit.LJCFJitUtilTraceinfoSym]; ok {
					ti2, err := od.FindTraceInfoFromLuaOpen()
					require.NoError(t, err)
					require.Equal(t, ti.Address, ti2.Address)
				}

				// Ditto for lj_dispatch_update
				if du, ok := od.FoundSymbols()[ljDispatchUpdateSym]; ok {
					du2, err := od.FindLjDispatchUpdateAddr()
					require.NoError(t, err)
					require.Equal(t, libpf.Address(du.Address), du2)
				}

				// TODO: strip binary and do it again.
			})
		}
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
								checkStruct(t, luajit.Trace{}, s, luajit.TracePartOffset)
							case "GCproto":
								checkStruct(t, luajit.ProtoRaw{}, s, protoRawOffset)
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

// getFrameSpace gets the expected value of cframeSize for the given
// architecture.
func getFrameSpace(machine elf.Machine) (int32, error) {
	switch machine {
	case elf.EM_AARCH64:
		return support.LJCframeSpaceArm, nil
	case elf.EM_X86_64:
		return support.LJCframeSpaceX86, nil
	default:
		return 0, fmt.Errorf("unsupported machine type: %s", machine)
	}
}

func extractStackDeltas(target string, ef *pfelf.File) (sdtypes.IntervalData, int32, error) {
	intervals, err := elfunwindinfo.Extract(target)
	if err != nil {
		return *intervals, 0, err
	}

	param, err := getFrameSpace(ef.Machine)
	if err != nil {
		return *intervals, 0, err
	}
	return *intervals, param, nil
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
