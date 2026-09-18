// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libc // import "go.opentelemetry.io/ebpf-profiler/libc"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestExtractTSDInfo(t *testing.T) {
	testCases := map[string]struct {
		machine elf.Machine
		code    []byte
		info    TSDInfo
	}{
		"musl 1.2.3 / Alpine 3.16 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x41, 0xd0, 0x3b, 0xd5, // mrs   x1, tpidr_el0
				0x21, 0x80, 0x5a, 0xf8, // ldur  x1, [x1, #-88]
				0x20, 0x58, 0x60, 0xf8, // ldr   x0, [x1, w0, uxtw #3]
				0xc0, 0x03, 0x5f, 0xd6, // ret
			},
			info: TSDInfo{
				Offset:     -88,
				Multiplier: 8,
				Indirect:   1,
			},
		},
		"glibc 2.35 / Fedora 36 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x5f, 0x24, 0x03, 0xd5, // bti     c
				0xe1, 0x03, 0x00, 0x2a, // mov     w1, w0
				0x1f, 0x7c, 0x00, 0x71, // cmp     w0, #0x1f
				0x48, 0x02, 0x00, 0x54, // b.hi    85bb4 <__pthread_getspecific+0x54>
				0x20, 0x7c, 0x7c, 0xd3, // ubfiz   x0, x1, #4, #32
				0x42, 0xd0, 0x3b, 0xd5, // mrs     x2, tpidr_el0
				0x00, 0xc0, 0x1a, 0xd1, // sub     x0, x0, #0x6b0
				0x42, 0x00, 0x00, 0x8b, // add     x2, x2, x0
				0x40, 0x04, 0x40, 0xf9, // ldr     x0, [x2, #8]
				0x40, 0x01, 0x00, 0xb4, // cbz     x0, 85bac <__pthread_getspecific+0x4c>
				0x21, 0x7c, 0x7c, 0xd3, // ubfiz   x1, x1, #4, #32
				0xe3, 0x08, 0x00, 0xd0, // adrp    x3, 1a3000 <intr+0x60>
				0x63, 0x40, 0x0a, 0x91, // add     x3, x3, #0x290
				0x44, 0x00, 0x40, 0xf9, // ldr     x4, [x2]
				0x61, 0x68, 0x61, 0xf8, // ldr     x1, [x3, x1]
				0x3f, 0x00, 0x04, 0xeb, // cmp     x1, x4
				0x41, 0x00, 0x00, 0x54, // b.ne    85ba8 <__pthread_getspecific+0x48>
				0xc0, 0x03, 0x5f, 0xd6, // ret
				// code skipped handling keys >0x1f
			},
			info: TSDInfo{
				Offset:     -0x6b0 + 8,
				Multiplier: 0x10,
			},
		},
		"glibc 2.33 / Fedora 34 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x5f, 0x24, 0x03, 0xd5, // bti     c
				0xe1, 0x03, 0x00, 0x2a, // mov     w1, w0
				0x1f, 0x7c, 0x00, 0x71, // cmp     w0, #0x1f
				0x48, 0x02, 0x00, 0x54, // b.hi    fb94 <__pthread_getspecific+0x54>  // b.pmore
				0x40, 0xd0, 0x3b, 0xd5, // mrs     x0, tpidr_el0
				0x22, 0x44, 0x00, 0x11, // add     w2, w1, #0x11
				0x00, 0x40, 0x1e, 0xd1, // sub     x0, x0, #0x790
				0x02, 0x10, 0x02, 0x8b, // add     x2, x0, x2, lsl #4
				0x40, 0x04, 0x40, 0xf9, // ldr     x0, [x2, #8]
				0x00, 0x01, 0x00, 0xb4, // cbz     x0, fb84 <__pthread_getspecific+0x44>
				0x21, 0x7c, 0x7c, 0xd3, // ubfiz   x1, x1, #4, #32
				0x03, 0x01, 0x00, 0xb0, // adrp    x3, 30000 <__nptl_nthreads>
				0x63, 0x80, 0x01, 0x91, // add     x3, x3, #0x60
				0x44, 0x00, 0x40, 0xf9, // ldr     x4, [x2]
				0x61, 0x68, 0x61, 0xf8, // ldr     x1, [x3, x1]
				0x3f, 0x00, 0x04, 0xeb, // cmp     x1, x4
				0x41, 0x00, 0x00, 0x54, // b.ne    fb88 <__pthread_getspecific+0x48>  // b.any
				0xc0, 0x03, 0x5f, 0xd6, // ret
				// code skipped handling keys >0x1f
			},
			info: TSDInfo{
				Offset:     -0x790 + (0x11 << 4) + 8,
				Multiplier: 0x10,
			},
		},
		"musl 1.2.3 / Alpine 3.16 / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				// mov    %fs:0x0,%rax
				// mov    0x80(%rax),%rax
				// mov    %edi,%edi
				// mov    (%rax,%rdi,8),%rax
				// ret
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00,
				0x00, 0x48, 0x8b, 0x80, 0x80, 0x00, 0x00, 0x00,
				0x89, 0xff, 0x48, 0x8b, 0x04, 0xf8, 0xc3,
			},
			info: TSDInfo{
				Offset:     0x80,
				Multiplier: 0x8,
				Indirect:   1,
			},
		},
		"musl 1.1.24 / Alpine 3.12 / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				// mov    %fs:0x0,%rax
				// mov    0x88(%rax),%rax
				// mov    %edi,%edi
				// mov    (%rax,%rdi,8),%rax
				// ret
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00,
				0x00, 0x48, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00,
				0x89, 0xff, 0x48, 0x8b, 0x04, 0xf8, 0xc3,
			},
			info: TSDInfo{
				Offset:     0x88,
				Multiplier: 0x8,
				Indirect:   1,
			},
		},
		"glibc 2.32 / Fedora 33 / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				// endbr64
				// cmp    $0x1f,%edi
				// ja     10bf0 <__pthread_getspecific+0x40>
				// lea    0x31(%rdi),%eax
				// shl    $0x4,%rax      # <- 0x31<<4 = 0x310, <<4 = *0x10
				// mov    %fs:0x10,%rdx
				// add    %rdx,%rax
				// mov    0x8(%rax),%r8  # <- +8
				// test   %r8,%r8
				// je     10beb <__pthread_getspecific+0x3b>
				// mov    %edi,%edi
				// lea    0xc4c2(%rip),%rdx # 1d0a0 <__GI___pthread_keys>
				// mov    (%rax),%rsi
				// shl    $0x4,%rdi
				// cmp    %rsi,(%rdx,%rdi,1)
				// jne    10c20 <__pthread_getspecific+0x70>
				// mov    %r8,%rax
				// retq
				// code skipped for handling keys >0x1f
				0xf3, 0x0f, 0x1e, 0xfa, 0x83, 0xff, 0x1f, 0x77,
				0x37, 0x8d, 0x47, 0x31, 0x48, 0xc1, 0xe0, 0x04,
				0x64, 0x48, 0x8b, 0x14, 0x25, 0x10, 0x00, 0x00,
				0x00, 0x48, 0x01, 0xd0, 0x4c, 0x8b, 0x40, 0x08,
				0x4d, 0x85, 0xc0, 0x74, 0x16, 0x89, 0xff, 0x48,
				0x8d, 0x15, 0xc2, 0xc4, 0x00, 0x00, 0x48, 0x8b,
				0x30, 0x48, 0xc1, 0xe7, 0x04, 0x48, 0x39, 0x34,
				0x3a, 0x75, 0x35, 0x4c, 0x89, 0xc0, 0xc3,
			},
			info: TSDInfo{
				Offset:     0x310 + 8,
				Multiplier: 0x10,
			},
		},
		"glibc 2.35  / Fedora 36 / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				// endbr64
				// cmp    $0x1f,%edi
				// ja     92a40 <__pthread_getspecific@GLIBC_2.2.5+0x40>
				// mov    %edi,%eax
				// add    $0x31,%rax
				// shl    $0x4,%rax
				// add    %fs:0x10,%rax
				// mov    0x8(%rax),%rdx
				// test   %rdx,%rdx
				// je     92a78 <__pthread_getspecific@GLIBC_2.2.5+0x78>
				// mov    %edi,%edi
				// lea    0x167b92(%rip),%rcx
				// mov    (%rax),%rsi
				// shl    $0x4,%rdi
				// cmp    %rsi,(%rcx,%rdi,1)
				// jne    92a70 <__pthread_getspecific@GLIBC_2.2.5+0x70>
				// mov    %rdx,%rax
				// ret
				// code skipped for handling keys >0x1f
				0xf3, 0x0f, 0x1e, 0xfa, 0x83, 0xff, 0x1f, 0x77,
				0x37, 0x89, 0xf8, 0x48, 0x83, 0xc0, 0x31, 0x48,
				0xc1, 0xe0, 0x04, 0x64, 0x48, 0x03, 0x04, 0x25,
				0x10, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x50, 0x08,
				0x48, 0x85, 0xd2, 0x74, 0x53, 0x89, 0xff, 0x48,
				0x8d, 0x0d, 0x92, 0x7b, 0x16, 0x00, 0x48, 0x8b,
				0x30, 0x48, 0xc1, 0xe7, 0x04, 0x48, 0x39, 0x34,
				0x39, 0x75, 0x35, 0x48, 0x89, 0xd0, 0xc3,
			},
			info: TSDInfo{
				Offset:     0x310 + 8,
				Multiplier: 0x10,
			},
		},
		"glibc 2.38 / Fedora 39 / arm64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x3f, 0x23, 0x03, 0xd5, // paciasp
				0xfd, 0x7b, 0xbf, 0xa9, // stp     x29, x30, [sp, #-16]!
				0xe1, 0x03, 0x00, 0x2a, // mov     w1, w0
				0xfd, 0x03, 0x00, 0x91, // mov     x29, sp
				0x1f, 0x7c, 0x00, 0x71, // cmp     w0, #0x1f
				// b.hi    91d98 <__pthread_getspecific@GLIBC_2.17+0x58>  // b.pmore
				0x28, 0x02, 0x00, 0x54,
				// mov     x0, #0xfffffffffffff9d0         // #-1584
				0xe0, 0xc5, 0x80, 0x92,
				0x42, 0xd0, 0x3b, 0xd5, // mrs     x2, tpidr_el0
				0x00, 0x50, 0x21, 0x8b, // add     x0, x0, w1, uxtw #4
				0x42, 0x00, 0x00, 0x8b, // add     x2, x2, x0
				0x40, 0x04, 0x40, 0xf9, // ldr     x0, [x2, #8]
				// cbz     x0, 91dcc <__pthread_getspecific@GLIBC_2.17+0x8c>
				0x00, 0x03, 0x00, 0xb4,
				0x21, 0x7c, 0x7c, 0xd3, // ubfiz   x1, x1, #4, #32
				0x83, 0x09, 0x00, 0xb0, // adrp    x3, 1c2000 <initial+0x198>
				0x63, 0x40, 0x17, 0x91, // add     x3, x3, #0x5d0
				0x44, 0x00, 0x40, 0xf9, // ldr     x4, [x2]
				0x61, 0x68, 0x61, 0xf8, // ldr     x1, [x3, x1]
				0x3f, 0x00, 0x04, 0xeb, // cmp     x1, x4
				// b.ne    91dc8 <__pthread_getspecific@GLIBC_2.17+0x88>  // b.any
				0x01, 0x02, 0x00, 0x54,
				0xfd, 0x7b, 0xc1, 0xa8, // ldp     x29, x30, [sp], #16
				0xbf, 0x23, 0x03, 0xd5, // autiasp
				0xc0, 0x03, 0x5f, 0xd6, // ret
				// code skipped handling keys >0x1f
			},
			info: TSDInfo{
				Offset:     -1584 + 8,
				Multiplier: 16,
			},
		},
		"booking coredump glibc": {
			machine: elf.EM_X86_64,
			code: []byte{
				0x83, 0xff, 0x1f, 0x77, 0x49, 0x89, 0xf8, 0x48, 0x83, 0xc0, 0x30, 0x48,
				0xc1, 0xe0, 0x04, 0x64, 0x48, 0x8b, 0x14, 0x25, 0x10, 0x00, 0x00, 0x00,
				0x48, 0x8d, 0x54, 0x02, 0x10, 0x48, 0x8b, 0x42, 0x08, 0x48, 0x85, 0xc0,
				0x74, 0x1a, 0x89, 0xff, 0x48, 0x8d, 0x0d, 0x61, 0xaa, 0x20, 0x00, 0x48,
				0xc1, 0xe7, 0x04, 0x48, 0x8b, 0x34, 0x39, 0x48, 0x39, 0x32, 0x75, 0x07,
				0xf3, 0xc3,
			},
			info: TSDInfo{
				Offset:     0x310 + 8,
				Multiplier: 0x10,
			},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			var info TSDInfo
			var err error
			switch test.machine {
			case elf.EM_X86_64:
				info, err = extractTSDInfoX86(test.code)
			case elf.EM_AARCH64:
				info, err = extractTSDInfoARM(test.code)
			}
			if assert.NoError(t, err) {
				assert.Equal(t, test.info, info, "Wrong TSD info extraction")
			}
		})
	}
}

func TestExtractDTVInfo(t *testing.T) {
	testCases := map[string]struct {
		soname  string
		machine elf.Machine
		info    DTVInfo
	}{
		"glibc / x86_64": {
			soname:  "libc.so.6",
			machine: elf.EM_X86_64,
			info:    DTVInfo{Offset: 8, Multiplier: 16},
		},
		"glibc / aarch64": {
			soname:  "libc.so.6",
			machine: elf.EM_AARCH64,
			info:    DTVInfo{Offset: 0, Multiplier: 16},
		},
		"glibc loader / x86_64": {
			soname:  "ld-linux-x86-64.so.2",
			machine: elf.EM_X86_64,
		},
		"glibc loader / aarch64": {
			soname:  "ld-linux-aarch64.so.1",
			machine: elf.EM_AARCH64,
		},
		"glibc libpthread": {
			soname:  "libpthread.so.0",
			machine: elf.EM_X86_64,
		},
		"no SONAME or musl symbol": {
			machine: elf.EM_X86_64,
		},
		"musl / x86_64": {
			soname:  "libc.musl-x86_64.so.1",
			machine: elf.EM_X86_64,
			info:    DTVInfo{Offset: 8, Multiplier: 8},
		},
		"musl / aarch64": {
			soname:  "libc.musl-aarch64.so.1",
			machine: elf.EM_AARCH64,
			info:    DTVInfo{Offset: -8, Multiplier: 8},
		},
		// An unknown C-library yields no DTV info rather than a guess.
		"unknown libc": {
			soname:  "libfoo.so.1",
			machine: elf.EM_X86_64,
		},
		"unsupported arch": {
			soname:  "libc.so.6",
			machine: elf.EM_RISCV,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			ef := buildTestELF(t, test.machine, test.soname, nil)
			assert.Equal(t, test.info, extractDTVInfo(ef))
		})
	}
}

func TestMuslDLS3Identification(t *testing.T) {
	for _, machine := range []elf.Machine{elf.EM_X86_64, elf.EM_AARCH64} {
		for _, test := range []struct {
			name   string
			soname string
			value  uint64
			size   uint64
			want   bool
		}{
			{name: "upstream without SONAME", value: 0x1000, size: 4, want: true},
			{name: "custom SONAME", soname: "libc.custom.so", value: 0x1000, size: 4, want: true},
			{name: "undefined function"},
			{name: "zero size", value: 0x1000, want: true},
			{name: "zero address", size: 4, want: true},
		} {
			t.Run(machine.String()+"/"+test.name, func(t *testing.T) {
				// The fixture has no section headers or static symbol table, as
				// neither should be needed to identify a stripped musl build.
				ef := buildTestELF(t, machine, test.soname,
					map[string][]byte{"__dls3": {0, 0, 0, 0}},
					func(_ string, sym *elf.Sym64) {
						sym.Value = test.value
						sym.Size = test.size
						if test.value == 0 && test.size == 0 {
							sym.Shndx = uint16(elf.SHN_UNDEF)
						}
					})
				want := DTVInfo{}
				if test.want {
					want = DTVInfo{Offset: 8, Multiplier: 8}
					if machine == elf.EM_AARCH64 {
						want.Offset = -8
					}
				}
				assert.Equal(t, want, extractDTVInfo(ef))
			})
		}
	}
}

func TestGlibcLoaderDoesNotPreemptDTVMetadata(t *testing.T) {
	// Model the loader and libpthread being processed before libc. Neither
	// may seed constants that Merge would retain instead of libc's metadata.
	var info LibcInfo
	for _, soname := range []string{"ld-linux-x86-64.so.2", "libpthread.so.0"} {
		ef := buildTestELF(t, elf.EM_X86_64, soname, nil)
		info.Merge(LibcInfo{DTVInfo: extractDTVInfo(ef)})
		assert.False(t, info.HasDTVInfo())
	}
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", glibcDTVSymbols(16, 2368, 192))
	info.Merge(LibcInfo{DTVInfo: extractDTVInfo(ef)})
	assert.Equal(t, DTVInfo{Offset: 16, Multiplier: 24}, info.DTVInfo)
}

func TestGlibcDTVInfo(t *testing.T) {
	// Descriptor values read from Debian 12 (glibc 2.36).
	testCases := map[string]struct {
		machine       elf.Machine
		dtvpOffset    uint32
		sizeofPthread uint32
		info          DTVInfo
	}{
		"x86_64": {
			machine:       elf.EM_X86_64,
			dtvpOffset:    8,
			sizeofPthread: 2368,
			info:          DTVInfo{Offset: 8, Multiplier: 16},
		},
		"aarch64": {
			machine:       elf.EM_AARCH64,
			dtvpOffset:    1856,
			sizeofPthread: 1856,
			info:          DTVInfo{Offset: 0, Multiplier: 16},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			ef := buildTestELF(t, test.machine, "libc.so.6", glibcDTVSymbols(
				test.dtvpOffset, test.sizeofPthread, 128))
			info, err := glibcDTVInfo(ef)
			require.NoError(t, err)
			assert.Equal(t, test.info, info)
		})
	}
}

func TestGlibcDTVInfoOverridesConstants(t *testing.T) {
	// A hypothetical glibc with a three pointer dtv_t and the DTV pointer one
	// word further into tcbhead_t.
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", glibcDTVSymbols(16, 2368, 192))
	assert.Equal(t, DTVInfo{Offset: 16, Multiplier: 24}, extractDTVInfo(ef))
}

func TestGlibcDTVInfoRejectsOffsetValue(t *testing.T) {
	// The BPF code cannot follow a DTV entry whose pointer is not first.
	syms := glibcDTVSymbols(8, 2368, 128)
	syms["_thread_db_dtv_t_pointer_val"] = dbDescBytes(64, 1, 8)
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", syms)
	_, err := glibcDTVInfo(ef)
	require.Error(t, err)

	// A layout we don't understand must not fall back to the static table,
	// which is known-stale for glibc >= 2.34.
	assert.Equal(t, DTVInfo{}, extractDTVInfo(ef))
}

func TestGlibcDTVInfoRejectsArrayOffset(t *testing.T) {
	// The BPF code indexes the dtv array straight from the dereferenced
	// pointer, with no leading header.
	syms := glibcDTVSymbols(8, 2368, 128)
	syms["_thread_db_dtv_dtv"] = dbDescBytes(128, 134217727, 8)
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", syms)
	_, err := glibcDTVInfo(ef)
	require.Error(t, err)
	assert.Equal(t, DTVInfo{}, extractDTVInfo(ef))
}

func glibcDTVSymbols(dtvpOffset, sizeofPthread, entrySizeBits uint32) map[string][]byte {
	return map[string][]byte{
		"_thread_db_dtv_dtv":           dbDescBytes(entrySizeBits, 134217727, 0),
		"_thread_db_pthread_dtvp":      dbDescBytes(64, 1, dtvpOffset),
		"_thread_db_dtv_t_pointer_val": dbDescBytes(64, 1, 0),
		"_thread_db_sizeof_pthread":    dbSizeofBytes(sizeofPthread),
	}
}

// dbDescBytes encodes an nptl_db uint32[3] field descriptor.
func dbDescBytes(sizeBits, nelem, offset uint32) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, sizeBits)
	b = binary.LittleEndian.AppendUint32(b, nelem)
	return binary.LittleEndian.AppendUint32(b, offset)
}

// dbSizeofBytes encodes an nptl_db _thread_db_sizeof_* value.
func dbSizeofBytes(size uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, size)
}

func glibcTSDSymbols(specificOffset, sizeofPthread uint32) map[string][]byte {
	return map[string][]byte{
		"_thread_db_pthread_specific":             dbDescBytes(2048, 1, specificOffset),
		"_thread_db_pthread_key_data_level2_data": dbDescBytes(128, 32, 0),
		"_thread_db_pthread_key_data_data":        dbDescBytes(64, 1, 8),
		"_thread_db_sizeof_pthread_key_data":      dbSizeofBytes(16),
		"_thread_db_sizeof_pthread":               dbSizeofBytes(sizeofPthread),
	}
}

func TestGlibcTSDInfo(t *testing.T) {
	// Descriptor values read from Debian 12 (glibc 2.36). The expected TSDInfo
	// is what extractTSDInfoX86/ARM recover from the same libraries.
	testCases := map[string]struct {
		machine        elf.Machine
		specificOffset uint32
		sizeofPthread  uint32
		info           TSDInfo
	}{
		"x86_64": {
			machine:        elf.EM_X86_64,
			specificOffset: 1296,
			sizeofPthread:  2368,
			info:           TSDInfo{Offset: 792, Multiplier: 16},
		},
		"aarch64": {
			machine:        elf.EM_AARCH64,
			specificOffset: 784,
			sizeofPthread:  1856,
			info:           TSDInfo{Offset: -1576, Multiplier: 16},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			ef := buildTestELF(t, test.machine, "libc.so.6", glibcTSDSymbols(
				test.specificOffset, test.sizeofPthread))
			info, err := glibcTSDInfo(ef)
			require.NoError(t, err)
			assert.Equal(t, test.info, info)

			// ExtractLibcInfo must prefer this over disassembly.
			libcInfo, err := ExtractLibcInfo(ef)
			require.NoError(t, err)
			assert.Equal(t, test.info, libcInfo.TSDInfo)
		})
	}
}

func TestGlibcTSDInfoRejectsMisalignedKeyDataSize(t *testing.T) {
	// level2_data's element size, in bits, must be a whole number of bytes.
	syms := glibcTSDSymbols(1296, 2368)
	syms["_thread_db_pthread_key_data_level2_data"] = dbDescBytes(129, 32, 0)
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", syms)
	_, err := glibcTSDInfo(ef)
	require.Error(t, err)
}

// buildTestELF creates a minimal 64-bit ELF binary with the given dynamic symbols.
// Each symbol maps to its corresponding code byte slice. The resulting ELF has a
// SysV hash table so pfelf.File can resolve symbols via LookupSymbol/SymbolData.
func buildTestELF(t *testing.T, machine elf.Machine, soname string,
	symbols map[string][]byte, symbolModifiers ...func(string, *elf.Sym64)) *pfelf.File {
	t.Helper()

	// Layout: ELF header | Phdr[0] PT_LOAD | Phdr[1] PT_DYNAMIC |
	//         strtab | symtab | hash | dyntab | code...
	//
	// Everything lives in one PT_LOAD segment starting at vaddr 0.
	const vaddr = uint64(0x1000)

	// Build string table: \0 then each symbol name \0-terminated
	var strtab bytes.Buffer
	strtab.WriteByte(0) // index 0 = empty string
	nameOffsets := make(map[string]uint32)
	for name := range symbols {
		nameOffsets[name] = uint32(strtab.Len())
		strtab.WriteString(name)
		strtab.WriteByte(0)
	}
	sonameOffset := uint32(strtab.Len())
	strtab.WriteString(soname)
	strtab.WriteByte(0)

	// Build symbol table: Sym64[0] is always null, then one per symbol
	numSyms := 1 + len(symbols)
	symtab := make([]elf.Sym64, numSyms)
	// Symbol index 0 is reserved (STN_UNDEF)

	// We'll fill in addresses after we know the code layout
	symOrder := make([]string, 0, len(symbols))
	for name := range symbols {
		symOrder = append(symOrder, name)
	}

	// sysvHash computes the ELF SysV hash for a symbol name.
	sysvHash := func(s string) uint32 {
		h := uint32(0)
		for _, c := range []byte(s) {
			h = 16*h + uint32(c)
			h ^= h >> 24 & 0xf0
		}
		return h & 0xfffffff
	}

	// Build SysV hash table
	// nbucket = numSyms, nchain = numSyms (simple 1:1 mapping)
	nbucket := uint32(numSyms)
	nchain := uint32(numSyms)

	// Now compute sizes for layout
	ehdrSize := int(binary.Size(elf.Header64{}))
	phdrSize := int(binary.Size(elf.Prog64{}))
	numPhdrs := 2

	strtabOff := ehdrSize + phdrSize*numPhdrs
	symtabOff := strtabOff + strtab.Len()
	hashOff := symtabOff + numSyms*int(binary.Size(elf.Sym64{}))
	hashSize := int(4 + 4 + 4*int(nbucket) + 4*int(nchain)) // nbucket, nchain, buckets, chains
	dynOff := hashOff + hashSize
	// STRTAB, SYMTAB, HASH, SONAME, NULL
	dynSize := 5 * int(binary.Size(elf.Dyn64{}))
	if soname == "" {
		dynSize -= int(binary.Size(elf.Dyn64{}))
	}
	codeOff := dynOff + dynSize

	// Place code for each symbol
	codeOffsets := make(map[string]int)
	offset := codeOff
	for _, name := range symOrder {
		codeOffsets[name] = offset
		offset += len(symbols[name])
	}
	totalSize := offset

	// Fill in symbol table entries
	for i, name := range symOrder {
		idx := i + 1 // skip null symbol at index 0
		symtab[idx] = elf.Sym64{
			Name:  nameOffsets[name],
			Info:  byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC),
			Other: byte(elf.STV_DEFAULT),
			Shndx: 1, // non-zero = defined
			Value: vaddr + uint64(codeOffsets[name]),
			Size:  uint64(len(symbols[name])),
		}
		for _, modify := range symbolModifiers {
			modify(name, &symtab[idx])
		}
	}

	// Build SysV hash: simple bucket[hash % nbucket] = sym_index, chain = 0
	hashBuf := make([]byte, hashSize)
	binary.LittleEndian.PutUint32(hashBuf[0:], nbucket)
	binary.LittleEndian.PutUint32(hashBuf[4:], nchain)
	bucketsStart := 8
	chainsStart := bucketsStart + 4*int(nbucket)

	// Initialize all buckets and chains to 0 (STN_UNDEF)
	for i, name := range symOrder {
		symIdx := uint32(i + 1)
		h := sysvHash(name)
		bucket := h % nbucket
		bucketOff := bucketsStart + 4*int(bucket)
		existing := binary.LittleEndian.Uint32(hashBuf[bucketOff:])
		if existing == 0 {
			binary.LittleEndian.PutUint32(hashBuf[bucketOff:], symIdx)
		} else {
			// Chain from existing
			cur := existing
			for {
				chainOff := chainsStart + 4*int(cur)
				next := binary.LittleEndian.Uint32(hashBuf[chainOff:])
				if next == 0 {
					binary.LittleEndian.PutUint32(hashBuf[chainOff:], symIdx)
					break
				}
				cur = next
			}
		}
	}

	// Build dynamic table
	dynEntries := []elf.Dyn64{
		{Tag: int64(elf.DT_STRTAB), Val: vaddr + uint64(strtabOff)},
		{Tag: int64(elf.DT_SYMTAB), Val: vaddr + uint64(symtabOff)},
		{Tag: int64(elf.DT_HASH), Val: vaddr + uint64(hashOff)},
	}
	if soname != "" {
		dynEntries = append(dynEntries, elf.Dyn64{Tag: int64(elf.DT_SONAME), Val: uint64(sonameOffset)})
	}
	dynEntries = append(dynEntries, elf.Dyn64{Tag: int64(elf.DT_NULL), Val: 0})

	// Assemble the ELF
	buf := make([]byte, totalSize)

	// ELF header
	hdr := elf.Header64{
		Ident:     [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(machine),
		Version:   uint32(elf.EV_CURRENT),
		Entry:     vaddr + uint64(codeOff),
		Phoff:     uint64(ehdrSize),
		Ehsize:    uint16(ehdrSize),
		Phentsize: uint16(phdrSize),
		Phnum:     uint16(numPhdrs),
	}
	binary.Encode(buf[0:], binary.LittleEndian, &hdr)

	// Program headers
	phLoad := elf.Prog64{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_R | elf.PF_X),
		Off:    0,
		Vaddr:  vaddr,
		Paddr:  vaddr,
		Filesz: uint64(totalSize),
		Memsz:  uint64(totalSize),
		Align:  0x1000,
	}
	binary.Encode(buf[ehdrSize:], binary.LittleEndian, &phLoad)

	phDyn := elf.Prog64{
		Type:   uint32(elf.PT_DYNAMIC),
		Flags:  uint32(elf.PF_R),
		Off:    uint64(dynOff),
		Vaddr:  vaddr + uint64(dynOff),
		Paddr:  vaddr + uint64(dynOff),
		Filesz: uint64(dynSize),
		Memsz:  uint64(dynSize),
		Align:  8,
	}
	binary.Encode(buf[ehdrSize+phdrSize:], binary.LittleEndian, &phDyn)

	// String table
	copy(buf[strtabOff:], strtab.Bytes())

	// Symbol table
	for i, sym := range symtab {
		binary.Encode(buf[symtabOff+i*int(binary.Size(elf.Sym64{})):], binary.LittleEndian, &sym)
	}

	// Hash table
	copy(buf[hashOff:], hashBuf)

	// Dynamic table
	for i, dyn := range dynEntries {
		binary.Encode(buf[dynOff+i*int(binary.Size(elf.Dyn64{})):], binary.LittleEndian, &dyn)
	}

	// Code sections
	for _, name := range symOrder {
		copy(buf[codeOffsets[name]:], symbols[name])
	}

	ef, err := pfelf.NewFile(bytes.NewReader(buf), 0, false)
	require.NoError(t, err)
	return ef
}

// A failed TSD extraction must not discard available DTV info.
func TestExtractLibcInfoIndependence(t *testing.T) {
	ef := buildTestELF(t, elf.EM_X86_64, "libc.so.6", nil)

	info, err := ExtractLibcInfo(ef)
	require.NoError(t, err)
	assert.False(t, info.HasTSDInfo())
	assert.True(t, info.HasDTVInfo())
}

func TestLibcInfoIsEqual(t *testing.T) {
	testCases := map[string]struct {
		left        LibcInfo
		right       LibcInfo
		expectEqual bool
	}{
		"empty libcinfos are equal": {
			left:        LibcInfo{},
			right:       LibcInfo{},
			expectEqual: true,
		},
		"nested values are equal": {
			left: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			right: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			expectEqual: true,
		},
		"nested values are not equal": {
			left: LibcInfo{
				TSDInfo{},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			right: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{},
			},
			expectEqual: false,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expectEqual, test.left.IsEqual(test.right))
		})
	}
}

func TestLibcInfoMerge(t *testing.T) {
	testCases := map[string]struct {
		left     LibcInfo
		right    LibcInfo
		expected LibcInfo
	}{
		"non-empty TSD values are accumulated from other": {
			left: LibcInfo{},
			right: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{},
			},
			expected: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{},
			},
		},
		"non-empty DTV values are accumulated from other": {
			left: LibcInfo{},
			right: LibcInfo{
				TSDInfo{},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			expected: LibcInfo{
				TSDInfo{},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
		},
		"non-empty TSD values are accumulated from other, with DTV already set": {
			left: LibcInfo{
				TSDInfo{},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			right: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{},
			},
			expected: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
		},
		"non-empty DTV values are accumulated from other, with TSD already set": {
			left: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{},
			},
			right: LibcInfo{
				TSDInfo{},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			expected: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
		},

		// This is not expected to actually happen, but we want to be clear
		// that values already present, if not empty, are kept and not reset
		"non-empty values are ignored if already set": {
			left: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
			right: LibcInfo{
				TSDInfo{
					Offset:     16,
					Multiplier: 16,
					Indirect:   0,
				},
				DTVInfo{
					Offset:     8,
					Multiplier: 16,
				},
			},
			expected: LibcInfo{
				TSDInfo{
					Offset:     8,
					Multiplier: 8,
					Indirect:   1,
				},
				DTVInfo{
					Offset:     -8,
					Multiplier: 16,
				},
			},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			merged := test.left
			merged.Merge(test.right)
			assert.True(t, test.expected.IsEqual(merged))
		})
	}
}
