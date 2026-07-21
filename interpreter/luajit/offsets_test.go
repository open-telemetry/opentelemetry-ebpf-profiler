// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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
				wantG2Dispatch := tc.exp.amd64G2Dispatch
				if platform == "linux/arm64" {
					wantG2Dispatch = tc.exp.arm64G2Dispatch
				}
				require.Equal(t, wantG2Dispatch, ljd.g2Dispatch,
					"g2Dispatch mismatch: a wrong value here makes the eBPF JIT "+
						"bootstrap emit bad-G candidates and starves luajit "+
						"triangulation in CI")

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
		{
			// The canonical form per lua_close's source uses `movq $0x0, OFS(reg)`
			// directly instead of zeroing a register first.
			name:          "immediate-zero-store",
			glRefExpected: 0x10,
			curLExpected:  0x170,
			code: []byte{
				0x48, 0x8b, 0x5f, 0x10, //                                     movq $0x10(%rdi), %rbx
				0x48, 0xc7, 0x83, 0x70, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movq $0x0, 0x170(%rbx)
			},
		},
		{
			// endbr64 prefix - the asm/amd interpreter skips it transparently
			// so we no longer need an explicit SkipEndBranch call.
			name:          "endbr64-prefix",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, //                                     endbr64
				0x48, 0x8b, 0x5f, 0x10, //                                     movq 0x10(%rdi), %rbx
				0x48, 0xc7, 0x83, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movq $0x0, 0x158(%rbx)
			},
		},
		{
			// Resilience case the old extractor would miss on two counts:
			//   1. R8 was zeroed via `xor %r8d, %r8d`; sameReg() only
			//      whitelisted EAX/ECX/EDX/EBX/ESI so R8/R8D would not match.
			//   2. The glref load is *not* directly from %rdi - the compiler
			//      first parked L in %rax, then loaded G via %rax. The old
			//      code required a1.Base == x86asm.RDI on the load.
			// Symbolic tracking handles both for free.
			name:          "r8-zero-and-rdi-mov-chain",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0x45, 0x31, 0xc0, //                                     xorl %r8d, %r8d
				0x48, 0x89, 0xf8, //                                     movq %rdi, %rax
				0x48, 0x8b, 0x58, 0x10, //                               movq 0x10(%rax), %rbx
				0x4c, 0x89, 0x83, 0x58, 0x01, 0x00, 0x00, //             movq %r8, 0x158(%rbx)
			},
		},
	}

	for _, test := range testdata {
		t.Run(test.name, func(t *testing.T) {
			x := x86Extractor{}
			glref, curL, err := x.findOffsetsFromLuaClose(test.code)
			require.NoError(t, err)
			require.Equal(t, test.glRefExpected, glref)
			require.Equal(t, test.curLExpected, curL)
		})
	}
}

func TestX86Checktrace(t *testing.T) {
	testdata := []struct {
		name     string
		expected uint64
		code     []byte
	}{
		{
			// Canonical jit_checktrace per the disasm comment in
			// extractor_x86.go: L (%rdi) is parked in %rbx, G is loaded as
			// L->glref via 0x10(%rbx), then the J->traces load is at
			// 0x430(%rdx).
			name:     "canonical",
			expected: 0x430,
			code: []byte{
				0x48, 0x89, 0xfb, //                         mov  %rdi, %rbx
				0x48, 0x8b, 0x53, 0x10, //                   mov  0x10(%rbx), %rdx
				0x48, 0x8b, 0x92, 0x30, 0x04, 0x00, 0x00, // mov  0x430(%rdx), %rdx
			},
		},
		{
			// SUB-shifted register: some builds apply a constant adjustment to
			// G's register before the final load. Old extractor accumulated
			// this manually; symbolic interpreter folds (-0xc + 0x43c) into
			// 0x430 via Add canonicalization. Recently broke in the wild
			// (#99ec409).
			name:     "sub-adjusted",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x83, 0xea, 0x0c, //                   sub  $0xc, %rdx
				0x48, 0x8b, 0x92, 0x3c, 0x04, 0x00, 0x00, // mov  0x43c(%rdx), %rdx
			},
		},
		{
			// ADD-shifted register: symmetric to the SUB case. (0xc + 0x424) = 0x430.
			name:     "add-adjusted",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x83, 0xc2, 0x0c, //                   add  $0xc, %rdx
				0x48, 0x8b, 0x92, 0x24, 0x04, 0x00, 0x00, // mov  0x424(%rdx), %rdx
			},
		},
		{
			// Resilience case: G is moved to an intermediate register before
			// the final load. Old extractor required the load's base to be
			// the same register that received the 0x10(L) load directly;
			// symbolic tracking propagates the value through the chain.
			name:     "mov-chain-through-intermediate-reg",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x89, 0xd6, //                         mov  %rdx, %rsi
				0x48, 0x8b, 0x8e, 0x30, 0x04, 0x00, 0x00, // mov  0x430(%rsi), %rcx
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.findG2TracesOffsetFromChecktrace(tc.code)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86LjDispatchUpdateAddr(t *testing.T) {
	testdata := []struct {
		name     string
		baseAddr uint64
		expected uint64
		code     []byte
	}{
		{
			// Canonical: stash L in callee-saved %rbx, then load G into %rdi
			// for the lj_dispatch_update call. CALL targets baseAddr+12+0xff4
			// = 0x1000.
			name:     "canonical-via-rbx",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x89, 0xfb, //                      mov  %rdi, %rbx
				0x48, 0x8b, 0x7b, 0x10, //                mov  0x10(%rbx), %rdi
				0xe8, 0xf4, 0x0f, 0x00, 0x00, //          call 0x1000
			},
		},
		{
			// Resilience case: the compiler loads G straight into %rdi without
			// first parking L in a separate register. The old extractor's
			// Lreg-then-load pattern required the stash; symbolic tracking
			// follows L's provenance through the self-overwrite of %rdi.
			name:     "direct-rdi-self-overwrite",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x8b, 0x7f, 0x10, //                mov  0x10(%rdi), %rdi
				0xe8, 0xf7, 0x0f, 0x00, 0x00, //          call 0x1000
			},
		},
		{
			// Earlier calls in the prologue do not have G in %rdi and must be
			// skipped over without consuming the result.
			name:     "skip-prologue-call",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x89, 0xfb, //                      mov  %rdi, %rbx
				0xe8, 0xf8, 0x04, 0x00, 0x00, //          call 0x500 (not dispatch_update)
				0x48, 0x8b, 0x7b, 0x10, //                mov  0x10(%rbx), %rdi
				0xe8, 0xef, 0x0f, 0x00, 0x00, //          call 0x1000 (dispatch_update)
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.findLjDispatchUpdateAddr(tc.code, tc.baseAddr)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86RipRelativeLea2ndArgTo2ndCall(t *testing.T) {
	// Two LEA-CALL pairs; both CALLs target 0x1000. After the 1st call's LEA
	// RSI = 0x500; after the 2nd's RSI = 0xa00. The function should return
	// 0xa00 (RSI's value at the 2nd matching CALL).
	code := []byte{
		0x48, 0x8d, 0x35, 0xf9, 0x04, 0x00, 0x00, // lea  0x4f9(%rip), %rsi  ; RSI = 0+7+0x4f9 = 0x500
		0xe8, 0xf4, 0x0f, 0x00, 0x00, //             call 0x1000             ; target=0+12+0xff4
		0x48, 0x8d, 0x35, 0xed, 0x09, 0x00, 0x00, // lea  0x9ed(%rip), %rsi  ; RSI = 0+19+0x9ed = 0xa00
		0xe8, 0xe8, 0x0f, 0x00, 0x00, //             call 0x1000             ; target=0+24+0xfe8
	}
	x := x86Extractor{}
	got, err := x.find2ndArgTo2ndPushClosureCall(code, 0, 0x1000)
	require.NoError(t, err)
	require.Equal(t, uint64(0xa00), got)
}

func TestX86Find4thArgToLibRegCall(t *testing.T) {
	testdata := []struct {
		name     string
		expected int64
		code     []byte
	}{
		{
			// Canonical luaopen_jit_util: lea $rip-rel, %rcx; ...; call lj_lib_register.
			// LEA at pos 4 (7 bytes), so RCX = 0 + 11 + 0xd21f5 = 0xd2200.
			name:     "lea-rip-relative",
			expected: 0xd2200,
			code: []byte{
				0x48, 0x83, 0xec, 0x08, //                   sub  $0x8, %rsp
				0x48, 0x8d, 0x0d, 0xf5, 0x21, 0x0d, 0x00, // lea  0xd21f5(%rip), %rcx
				0xe8, 0xf0, 0xff, 0x01, 0x00, //             call (target irrelevant)
			},
		},
		{
			// Some compilers materialize the 4th arg via `mov $imm, %ecx`.
			name:     "mov-immediate",
			expected: 0x1234,
			code: []byte{
				0xb9, 0x34, 0x12, 0x00, 0x00, //             mov  $0x1234, %ecx
				0xe8, 0xfb, 0x1f, 0x00, 0x00, //             call (target irrelevant)
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.find4thArgToLibRegCall(tc.code, 0)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86Find3rdArgToLibPreregCall(t *testing.T) {
	// Construct a minimal AABA call sequence (A=0x1000, B=0x2000) followed by
	// 3 more CALLs, with `lea $rip-rel, %rdx` immediately before the 3rd.
	// AABA section occupies bytes 0-19; the post-AABA interpreter section
	// runs from byte 20 onward with CodeAddress=20:
	//   pos 20-24: CALL (target irrelevant - 1st post-AABA)
	//   pos 25-29: CALL                                (2nd)
	//   pos 30-36: LEA  0x3fdb(%rip), %rdx  -> RDX = 20 + 17 + 0x3fdb = 0x4000
	//   pos 37-41: CALL                                (3rd - read RDX here)
	code := []byte{
		// AABA: A, A, B, A (A=0x1000, B=0x2000), each call is 5 bytes
		0xe8, 0xfb, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 0)
		0xe8, 0xf6, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 5)
		0xe8, 0xf1, 0x1f, 0x00, 0x00, //                 call 0x2000   (B, pos 10)
		0xe8, 0xec, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 15) -> ip=20

		// Post-AABA section interpreted with CodeAddress=20.
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (1st post-AABA, pos 20)
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (2nd post-AABA, pos 25)
		0x48, 0x8d, 0x15, 0xdb, 0x3f, 0x00, 0x00, //     lea  0x3fdb(%rip), %rdx
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (3rd post-AABA, pos 37)
	}
	x := x86Extractor{}
	got, err := x.find3rdArgToLibPreregCall(code, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(0x4000), got)
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
