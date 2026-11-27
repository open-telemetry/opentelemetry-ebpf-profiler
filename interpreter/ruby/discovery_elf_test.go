// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tls"
)

// A small ELF with real dynamic symbols, hashes, relocations and PT_TLS lets
// these tests exercise the complete discovery path without distro binaries.
type rubyTestELF struct {
	machine  elf.Machine
	code     [][]byte
	relocs   []elf.Rela64
	resolver string
	offsets  [2]uint64
	plt      []byte
}

func (f rubyTestELF) open(t *testing.T) *pfelf.File {
	t.Helper()
	data := make([]byte, 0x6800)
	put := func(offset int, value any) {
		var b bytes.Buffer
		require.NoError(t, binary.Write(&b, binary.LittleEndian, value))
		copy(data[offset:], b.Bytes())
	}
	strings := []byte{0}
	addString := func(name string) uint32 {
		offset := uint32(len(strings))
		strings = append(append(strings, name...), 0)
		return offset
	}
	syms := []elf.Sym64{{}, {Name: addString(f.resolver), Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)}}
	for i, name := range []string{"rb_thread_current", "rb_fiber_current", "rb_current_receiver"} {
		address := 0x1000 + i*0x100
		copy(data[address:], f.code[i])
		syms = append(syms, elf.Sym64{Name: addString(name), Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC),
			Shndx: 1, Value: uint64(address), Size: uint64(len(f.code[i]))})
	}
	copy(data[0x5000:], strings)
	put(0x5100, syms)
	// One SysV hash bucket, chaining every dynamic symbol.
	hash := []uint32{1, uint32(len(syms)), 1, 0}
	for i := 1; i < len(syms); i++ {
		hash = append(hash, uint32((i+1)%len(syms)))
	}
	put(0x5300, hash)
	put(0x5400, f.relocs)
	dynamic := []elf.Dyn64{{Tag: int64(elf.DT_SYMTAB), Val: 0x5100},
		{Tag: int64(elf.DT_STRTAB), Val: 0x5000}, {Tag: int64(elf.DT_STRSZ), Val: uint64(len(strings))},
		{Tag: int64(elf.DT_HASH), Val: 0x5300}, {Tag: int64(elf.DT_NULL)}}
	put(0x5700, dynamic)
	put(0x3018, f.offsets[0])
	put(0x3028, f.offsets[1])
	// Direct calls use an ENDBR64-prefixed PLT stub targeting the resolver GOT.
	copy(data[0x1400:], []byte{0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25})
	put(0x1406, int32(0x3000-0x140a))
	if f.plt != nil {
		copy(data[0x1400:], f.plt)
	}
	strings = []byte{0}
	sections := []elf.Section64{{},
		{Name: addString(".text"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Off: 0x1000, Size: 0x1000},
		{Name: addString(".got"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Addr: 0x3000, Off: 0x3000, Size: 0x100},
		{Name: addString(".tdata"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS), Addr: 0x4000, Off: 0x4000, Size: 64},
		{Name: addString(".dynstr"), Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_ALLOC), Addr: 0x5000, Off: 0x5000, Size: dynamic[2].Val},
		{Name: addString(".dynsym"), Type: uint32(elf.SHT_DYNSYM), Flags: uint64(elf.SHF_ALLOC), Addr: 0x5100, Off: 0x5100, Size: uint64(len(syms) * 24), Link: 4, Entsize: 24},
		{Name: addString(".hash"), Type: uint32(elf.SHT_HASH), Flags: uint64(elf.SHF_ALLOC), Addr: 0x5300, Off: 0x5300, Size: uint64(len(hash) * 4), Link: 5},
		{Name: addString(".rela.dyn"), Type: uint32(elf.SHT_RELA), Flags: uint64(elf.SHF_ALLOC), Addr: 0x5400, Off: 0x5400, Size: uint64(len(f.relocs) * 24), Link: 5, Entsize: 24},
		{Name: addString(".dynamic"), Type: uint32(elf.SHT_DYNAMIC), Flags: uint64(elf.SHF_ALLOC), Addr: 0x5700, Off: 0x5700, Size: uint64(len(dynamic) * 16), Link: 4, Entsize: 16},
		{Name: addString(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: 0x5900},
	}
	sections[9].Size = uint64(len(strings))
	copy(data[0x5900:], strings)
	put(0x6000, sections)
	put(0, elf.Header64{Ident: [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1},
		Type: uint16(elf.ET_DYN), Machine: uint16(f.machine), Version: 1, Ehsize: 64,
		Phoff: 64, Phentsize: 56, Phnum: 3, Shoff: 0x6000, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: 9})
	put(64, []elf.Prog64{
		{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W | elf.PF_X), Filesz: uint64(len(data)), Memsz: uint64(len(data)), Align: 4096},
		{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R), Off: 0x5700, Vaddr: 0x5700, Filesz: uint64(len(dynamic) * 16), Memsz: uint64(len(dynamic) * 16)},
		{Type: uint32(elf.PT_TLS), Flags: uint32(elf.PF_R), Off: 0x4000, Vaddr: 0x4000, Filesz: 64, Memsz: 64, Align: 8},
	})
	ef, err := pfelf.NewFile(bytes.NewReader(data), 0, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ef.Close()) })
	return ef
}

func rubyTestARMInline(slot uint32) []byte {
	// The function and the descriptor are two pages apart.
	words := []uint32{0xd53bd041, 0xd0000000, // MRS X1, TP; ADRP X0, +0x2000
		0xf9400002 | ((slot & 4095) / 8 << 10), // LDR X2, [X0, slot]
		0x91000000 | ((slot & 4095) << 10),     // ADD X0, X0, slot
		0xd63f0040, 0xf8606820, 0xd65f03c0}     // BLR X2; LDR X0, [X1,X0]; RET
	code := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(code[i*4:], word)
	}
	return code
}

func TestRubyARMECRelocations(t *testing.T) {
	for _, name := range []string{"distinct-descriptors", "conflicting-offsets", "missing-descriptor", "named-descriptor", "empty-named-descriptor", "negative-offset", "unaligned-offset", "outside-tls"} {
		t.Run(name, func(t *testing.T) {
			f := rubyTestELF{machine: elf.EM_AARCH64, resolver: "__tls_get_addr",
				code: [][]byte{rubyTestARMInline(0x3010), rubyTestARMInline(0x3010), rubyTestARMInline(0x3020)},
				relocs: []elf.Rela64{{Off: 0x3010, Info: uint64(elf.R_AARCH64_TLSDESC), Addend: 8},
					{Off: 0x3020, Info: uint64(elf.R_AARCH64_TLSDESC), Addend: 8}}}
			switch name {
			case "conflicting-offsets":
				f.relocs[1].Addend = 16
			case "missing-descriptor":
				f.relocs = f.relocs[:1]
			case "named-descriptor":
				f.relocs[0].Info |= 1 << 32
			case "empty-named-descriptor":
				f.resolver = ""
				f.relocs[0].Info |= 1 << 32
			case "negative-offset", "unaligned-offset", "outside-tls":
				value := map[string]int64{"negative-offset": -1, "unaligned-offset": 9, "outside-tls": 64}[name]
				f.relocs[0].Addend, f.relocs[1].Addend = value, value
			}
			sym, err := discoverRubyEC(f.open(t))
			if name != "distinct-descriptors" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.EqualValues(t, 8, sym.Address)
			require.Equal(t, elf.STT_TLS, elf.ST_TYPE(sym.Info))
		})
	}
}

func TestRubyAMDResolverRequiresJump(t *testing.T) {
	// Padding immediately before a GOT relocation is not a resolver stub.
	f := rubyTestELF{machine: elf.EM_X86_64, resolver: "__tls_get_addr",
		code: [][]byte{{0xc3}, {0xc3}, {0xc3}}, plt: bytes.Repeat([]byte{0x90}, 16),
		relocs: []elf.Rela64{{Off: 0x1410, Info: 1<<32 | uint64(elf.R_X86_64_GLOB_DAT)}}}
	err := rubyAMDResolver(f.open(t), rubyTLSAccess{resolverCall: 0x1400})
	require.Error(t, err)
}

func rubyTestAMDCall(address, slot uint64, indirect bool) []byte {
	code := []byte{0x48, 0x8d, 0x3d, 0, 0, 0, 0} // LEA RDI, [RIP+slot]
	binary.LittleEndian.PutUint32(code[3:], uint32(slot-address-7))
	if indirect {
		code = append(code, 0xff, 0x15, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(code[9:], uint32(0x3000-address-13))
	} else {
		code = append(code, 0xe8, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(code[8:], uint32(0x1400-address-12))
	}
	return append(code, 0x5d, 0x48, 0x8b, 0, 0xc3) // POP RBP; MOV RAX, [RAX]; RET
}

func TestRubyAMDECDisplacedAccess(t *testing.T) {
	// One getter uses a tls_index for the variable; the other uses the module
	// base and a displaced load. They must identify the same TLS variable.
	fiber := rubyTestAMDCall(0x1100, 0x3020, true)
	fiber = append(fiber[:len(fiber)-4], 0x48, 0x8b, 0x40, 0x10, 0xc3) // MOV RAX,[RAX+16]; RET
	f := rubyTestELF{machine: elf.EM_X86_64, resolver: "__tls_get_addr", offsets: [2]uint64{16, 0},
		code: [][]byte{rubyTestAMDCall(0x1000, 0x3010, false), fiber, {0xc3}},
		relocs: []elf.Rela64{{Off: 0x3000, Info: 1<<32 | uint64(elf.R_X86_64_GLOB_DAT)},
			{Off: 0x3010, Info: uint64(elf.R_X86_64_DTPMOD64)}, {Off: 0x3020, Info: uint64(elf.R_X86_64_DTPMOD64)}}}
	ef := f.open(t)
	ec, err := discoverRubyEC(ef)
	require.NoError(t, err)
	require.EqualValues(t, 16, ec.Address)
	got, err := tls.Resolve(ef, ec)
	require.NoError(t, err)
	want, err := tls.ResolveAccessor(ef, "rb_fiber_current")
	require.NoError(t, err)
	require.Equal(t, want, got)

	// Unsigned wrapping of tls_index.offset + displacement would also yield 16.
	f.offsets[1] = ^uint64(0) - 15
	fiber[len(fiber)-2] = 32
	_, err = discoverRubyEC(f.open(t))
	require.Error(t, err)
}

func TestRubyAMDECRelocations(t *testing.T) {
	for _, name := range []string{"mixed-calls", "plt-relocation", "wrong-resolver", "wrong-relocation", "missing-resolver", "conflicting-offsets", "outside-tls", "named-tls"} {
		t.Run(name, func(t *testing.T) {
			f := rubyTestELF{machine: elf.EM_X86_64, resolver: "__tls_get_addr", offsets: [2]uint64{16, 16},
				code: [][]byte{rubyTestAMDCall(0x1000, 0x3010, false), rubyTestAMDCall(0x1100, 0x3020, true), {0xc3}},
				relocs: []elf.Rela64{{Off: 0x3000, Info: 1<<32 | uint64(elf.R_X86_64_GLOB_DAT)},
					{Off: 0x3010, Info: uint64(elf.R_X86_64_DTPMOD64)}, {Off: 0x3020, Info: uint64(elf.R_X86_64_DTPMOD64)}}}
			switch name {
			case "plt-relocation":
				f.relocs[0].Info = 1<<32 | uint64(elf.R_X86_64_JMP_SLOT)
			case "wrong-resolver":
				f.resolver = "not_tls_get_addr"
			case "wrong-relocation":
				f.relocs[0].Info = 1<<32 | uint64(elf.R_X86_64_RELATIVE)
			case "missing-resolver":
				f.relocs = f.relocs[1:]
			case "conflicting-offsets":
				f.offsets[1] = 24
			case "outside-tls":
				f.offsets = [2]uint64{64, 64}
			case "named-tls":
				f.relocs[1].Info |= 1 << 32
			}
			sym, err := discoverRubyEC(f.open(t))
			if name != "mixed-calls" && name != "plt-relocation" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.EqualValues(t, 16, sym.Address)
		})
	}
}
