#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Remove BTF line-info debug data from an eBPF ELF object.

The tracer blob is built with -g, which makes clang embed BTF line
info into the object: .BTF.ext carries one line-info record per
instruction, and the string table of .BTF carries the literal source
text of every line of code that contributed an instruction. Both
roughly double the size of the shipped blob, and are only needed to
annotate verifier error messages with source file and line numbers.

This tool:
1. rewrites .BTF.ext keeping only func_info (the kernel verifier needs
   it to type-check callback arguments of helpers like bpf_find_vma)
   and dropping the line info, and
2. rewrites the .BTF string table, dropping all strings that are no
   longer referenced by the BTF type graph or by .BTF.ext.

The .rel.BTF and .rel.BTF.ext sections are removed by the strip step
in the Makefile. The BTF type graph and the .BTF datasec entries are
kept: the loader needs them to set up the eBPF maps. Type IDs do not
change, so the symbol table stays valid. Note that (2) requires (1)
to have run, as line info references strings in the .BTF string
table.

Usage: clean_btf.py <file>...
"""

import os
import struct
import sys
import tempfile

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_NOBITS = 8
EHDR_SIZE = 64
SHDR_SIZE = 64
BTF_MAGIC = 0xEB9F
BPF_LINE_INFO_SIZE = 16
LINE_INFO_STUB_SIZE = 4


def fail(msg):
    raise SystemExit(f"clean_btf: {msg}")


def btf_name_slots(types):
    """Offsets of every name_off field within the .BTF type section.

    Walks the type graph record by record. Kinds are per the BTF UAPI;
    anything unknown is rejected rather than guessed at.
    """
    slots = []
    off = 0
    n = len(types)
    while off < n:
        if off + 12 > n:
            fail(".BTF: truncated BTF type")
        info, = struct.unpack_from("<I", types, off + 4)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        slots.append(off)  # common name_off
        body = off + 12
        if kind == 1:    # BTF_KIND_INT: bits/encoding
            body += 4
        elif kind == 3:  # BTF_KIND_ARRAY: type, index_type, nelems
            body += 12
        elif kind in (4, 5):  # BTF_KIND_STRUCT/UNION members
            slots.extend(range(body, body + 12 * vlen, 12))
            body += 12 * vlen
        elif kind == 6:  # BTF_KIND_ENUM values
            slots.extend(range(body, body + 8 * vlen, 8))
            body += 8 * vlen
        elif kind == 13:  # BTF_KIND_FUNC_PROTO params
            slots.extend(range(body, body + 8 * vlen, 8))
            body += 8 * vlen
        elif kind == 14:  # BTF_KIND_VAR: linkage
            body += 4
        elif kind == 15:  # BTF_KIND_DATASEC vars: type, offset, size
            body += 12 * vlen
        elif kind == 17:  # BTF_KIND_DECL_TAG: component_idx
            body += 4
        elif kind == 19:  # BTF_KIND_ENUM64 values
            slots.extend(range(body, body + 12 * vlen, 12))
            body += 12 * vlen
        elif kind not in (0, 2, 7, 8, 9, 10, 11, 12, 16, 18):
            # VOID, PTR, FORWARD, TYPEDEF, VOLATILE, CONST, RESTRICT,
            # FUNC, FLOAT, TYPE_TAG have no kind specific data.
            fail(f".BTF: unsupported BTF kind {kind}")
        if body > n:
            fail(".BTF: truncated BTF type")
        off = body
    return slots


class ELF:
    def __init__(self, path):
        with open(path, "rb") as f:
            data = f.read()

        self.path = path
        self.original_size = len(data)
        self.ehdr = bytearray(data[:EHDR_SIZE])

        if data[:4] != ELF_MAGIC:
            fail(f"{path}: not an ELF file")
        if data[4] != ELFCLASS64:
            fail(f"{path}: not a 64-bit ELF file")
        if data[5] != ELFDATA2LSB:
            fail(f"{path}: not a little-endian ELF file")

        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

        if self.e_phnum != 0:
            fail(f"{path}: program headers are not supported")
        if self.e_ehsize != EHDR_SIZE or self.e_shentsize != SHDR_SIZE:
            fail(f"{path}: unexpected ELF header or section header size")

        shstr_hdr = self.e_shoff + self.e_shstrndx * SHDR_SIZE
        shstr_off, shstr_size = struct.unpack_from("<QQ", data, shstr_hdr + 24)
        shstr = data[shstr_off:shstr_off + shstr_size]

        self.sections = []
        for i in range(self.e_shnum):
            h = self.e_shoff + i * SHDR_SIZE
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize) = \
                struct.unpack_from("<IIQQQQIIQQ", data, h)
            end = shstr.index(b"\0", sh_name)
            name = shstr[sh_name:end].decode()
            if sh_type == SHT_NOBITS:
                blob = b""
            else:
                if sh_offset + sh_size > len(data):
                    fail(f"{path}: section {i} extends past end of file")
                blob = data[sh_offset:sh_offset + sh_size]
            self.sections.append(
                dict(name=name, sh_name=sh_name, sh_type=sh_type,
                     sh_flags=sh_flags, sh_addr=sh_addr, sh_offset=sh_offset,
                     sh_size=sh_size, sh_link=sh_link, sh_info=sh_info,
                     sh_addralign=sh_addralign, sh_entsize=sh_entsize,
                     data=blob))

    def find(self, name):
        for i, sec in enumerate(self.sections):
            if sec["name"] == name:
                return i
        return -1

    def strip_btf_ext_line_info(self):
        """Rewrite .BTF.ext keeping only its func_info records."""
        idx = self.find(".BTF.ext")
        if idx < 0:
            return False
        sec = self.sections[idx]
        data = sec["data"]

        (magic, version, flags, hdr_len, func_off, func_len, line_off,
         line_len) = struct.unpack_from("<HBBIIIII", data, 0)
        if magic != BTF_MAGIC:
            fail(f"{self.path}: .BTF.ext: bad magic {magic:#x}")
        if version != 1:
            fail(f"{self.path}: .BTF.ext: unsupported version {version}")
        if hdr_len not in (24, 32):
            fail(f"{self.path}: .BTF.ext: unsupported header size {hdr_len}")
        if (line_len == 0 or line_len == LINE_INFO_STUB_SIZE) and \
                len(data) == hdr_len + func_off + func_len + line_len:
            return False  # already stripped
        if line_off != func_off + func_len:
            fail(f"{self.path}: .BTF.ext: unexpected record layout")
        if func_len == 0:
            fail(f"{self.path}: .BTF.ext: missing func_info")

        header = struct.pack("<HBBIIIII", magic, version, flags, hdr_len,
                             func_off, func_len, func_off + func_len,
                             LINE_INFO_STUB_SIZE)
        if hdr_len == 32:
            core_relo_off, core_relo_len = struct.unpack_from("<II", data, 24)
            if core_relo_len != 0:
                fail(f"{self.path}: .BTF.ext: CO-RE relocations are not "
                     f"supported")
            header += struct.pack("<II", 0, 0)

        # Keep a minimal (empty) line_info region: loaders like cilium/ebpf
        # parse the line_info segment unconditionally and error out on an
        # empty one, but accept a segment that only holds the record size.
        sec["data"] = (header +
                       data[hdr_len + func_off:hdr_len + func_off + func_len] +
                       struct.pack("<I", BPF_LINE_INFO_SIZE))
        sec["sh_size"] = len(sec["data"])
        return True

    def btf_ext_string_refs(self):
        """String offsets referenced by the .BTF.ext section entries.

        The func_info entries of .BTF.ext name their ELF section via an
        offset into the .BTF string table. Returns the referenced
        offsets plus the positions of those fields, so they can be
        remapped when the .BTF string table is rewritten.
        """
        refs = set()
        slots = []
        idx = self.find(".BTF.ext")
        if idx < 0:
            return refs, slots
        data = self.sections[idx]["data"]
        (_, _, _, hdr_len, func_off, func_len, _, _) = \
            struct.unpack_from("<HBBIIIII", data, 0)
        if func_len == 0:
            return refs, slots

        pos = hdr_len + func_off
        end = pos + func_len
        rec_size, = struct.unpack_from("<I", data, pos)
        pos += 4
        while pos < end:
            refs.add(struct.unpack_from("<I", data, pos)[0])
            slots.append(pos)
            num_info = struct.unpack_from("<I", data, pos + 4)[0]
            pos += 8 + num_info * rec_size
        if pos != end:
            fail(f"{self.path}: malformed .BTF.ext func_info")
        return refs, slots

    def purge_btf_unused_strings(self):
        """Rewrite the .BTF string table keeping only referenced strings."""
        idx = self.find(".BTF")
        if idx < 0:
            return False

        sec = self.sections[idx]
        data = sec["data"]
        (magic, version, flags, hdr_len, type_off, type_len, str_off,
         str_len) = struct.unpack_from("<HBBIIIII", data, 0)
        if magic != BTF_MAGIC:
            fail(f"{self.path}: .BTF: bad magic {magic:#x}")
        if version != 1:
            fail(f"{self.path}: .BTF: unsupported version {version}")

        types = data[hdr_len + type_off:hdr_len + type_off + type_len]
        strings = data[hdr_len + str_off:hdr_len + str_off + str_len]

        refs, ext_name_slots = self.btf_ext_string_refs()
        name_slots = btf_name_slots(types)
        for slot in name_slots:
            off, = struct.unpack_from("<I", types, slot)
            if off >= len(strings):
                fail(f"{self.path}: .BTF: string offset {off} out of range")
            refs.add(off)

        # Rebuild the string table in original order. Offset 0 (the empty
        # string) is always kept.
        mapping = {}
        new_strings = bytearray()
        pos = 0
        while pos < len(strings):
            end = strings.index(b"\0", pos)
            if pos == 0 or pos in refs:
                mapping[pos] = len(new_strings)
                new_strings += strings[pos:end] + b"\0"
            pos = end + 1
        for off in refs:
            if off not in mapping:
                fail(f"{self.path}: .BTF: string at offset {off} was not "
                     f"found in the string table")

        new_types = bytearray(types)
        for slot in name_slots:
            off, = struct.unpack_from("<I", types, slot)
            struct.pack_into("<I", new_types, slot, mapping[off])

        # Remap the .BTF.ext section name offsets into the new table.
        ext_idx = self.find(".BTF.ext")
        if ext_idx >= 0:
            ext_data = bytearray(self.sections[ext_idx]["data"])
            for slot in ext_name_slots:
                off, = struct.unpack_from("<I", ext_data, slot)
                struct.pack_into("<I", ext_data, slot, mapping[off])
            self.sections[ext_idx]["data"] = bytes(ext_data)

        new_data = (struct.pack("<HBBIIIII", magic, version, flags, hdr_len,
                                0, len(new_types), len(new_types),
                                len(new_strings)) +
                    new_types + new_strings)
        if new_data == data:
            return False
        sec["data"] = new_data
        sec["sh_size"] = len(new_data)
        return True

    def write(self, out_path):
        # Lay out: ELF header, section data, section header table.
        out = bytearray(self.ehdr)
        cursor = EHDR_SIZE
        for idx, sec in enumerate(self.sections):
            if idx == 0:
                sec["sh_offset"] = 0
                continue
            align = sec["sh_addralign"] or 1
            cursor = (cursor + align - 1) & ~(align - 1)
            sec["sh_offset"] = cursor
            if sec["sh_type"] == SHT_NOBITS:
                continue
            out += b"\0" * (cursor - len(out))
            out += sec["data"]
            cursor = len(out)
        cursor = (cursor + 7) & ~7
        e_shoff = cursor
        out += b"\0" * (e_shoff - len(out))

        for sec in self.sections:
            out += struct.pack("<IIQQQQIIQQ", sec["sh_name"], sec["sh_type"],
                               sec["sh_flags"], sec["sh_addr"],
                               sec["sh_offset"], sec["sh_size"],
                               sec["sh_link"], sec["sh_info"],
                               sec["sh_addralign"], sec["sh_entsize"])

        struct.pack_into("<Q", out, 40, e_shoff)             # e_shoff
        struct.pack_into("<H", out, 60, len(self.sections))  # e_shnum
        struct.pack_into("<H", out, 62, self.e_shstrndx)     # e_shstrndx

        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(out_path) or ".",
            prefix=os.path.basename(out_path) + ".")
        try:
            os.chmod(tmp_path, os.stat(out_path).st_mode & 0o7777)
            with os.fdopen(fd, "wb") as f:
                f.write(out)
            os.replace(tmp_path, out_path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        return len(out)


def main(argv):
    if len(argv) < 2:
        fail(f"usage: {argv[0]} <file>...")

    for path in argv[1:]:
        elf = ELF(path)
        stripped = elf.strip_btf_ext_line_info()
        purged = elf.purge_btf_unused_strings()
        if not stripped and not purged:
            print(f"{path}: no BTF debug data found, nothing to do")
            continue
        new_size = elf.write(path)
        print(f"{path}: removed BTF line info "
              f"({elf.original_size} -> {new_size} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
