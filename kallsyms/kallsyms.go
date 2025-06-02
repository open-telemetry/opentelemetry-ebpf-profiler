// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package kallsyms provides functionality for reading /proc/kallsyms
// and using it to symbolize kernel addresses.
package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

const (
	kallsymsPath = "/proc/kallsyms"

	Kernel = "vmlinux"

	pointerBits = int(unsafe.Sizeof(libpf.Address(0)) * 8)
)

var ErrSymbolPermissions = errors.New("unable to read kallsyms addresses - check capabilities")

var ErrNoModule = errors.New("module not found")

var ErrNoSymbol = errors.New("symbol not found")

type symbol struct {
	offset uint32 // symbol offset from module start
	index  uint32 // symbol name offset within module 'names' data
}

type Module struct {
	start libpf.Address
	end   libpf.Address
	mtime time.Time

	buildID string
	fileID  libpf.FileID
	names   []byte
	symbols []symbol
}

type Symbolizer struct {
	valid atomic.Bool

	modules []Module
}

func NewSymbolizer() *Symbolizer {
	return &Symbolizer{}
}

func (m *Module) addName(name string) uint32 {
	index := len(m.names)
	l := len(name)
	m.names = append(m.names, byte(l))
	m.names = append(m.names, stringutil.String2ByteSlice(name)...)
	return uint32(index)
}

func (m *Module) bytesAt(index uint32) []byte {
	i := int(index)
	return m.names[i+1 : i+1+int(m.names[i])]
}

func (m *Module) stringAt(index uint32) string {
	return stringutil.ByteSlice2String(m.bytesAt(index))
}

func getSysfsMtime(mod string) time.Time {
	if mod == Kernel {
		return time.Time{}
	}
	if info, err := os.Stat(path.Join("/sys/module", mod)); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

func parseSysfsUint(mod, knob string) (uint64, error) {
	text, err := os.ReadFile(path.Join("/sys/module", mod, knob))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.Trim(stringutil.ByteSlice2String(text), "\n"), 0, pointerBits)
}

func (m *Module) init(mod string) {
	// Record module name
	m.addName(mod)

	// Determine notes location and module size
	notesFile := "/sys/kernel/notes"
	if mod != Kernel {
		notesFile = path.Join("/sys/module", mod, "notes/.note.gnu.build-id")

		if addr, err := parseSysfsUint(mod, "sections/.text"); err == nil {
			m.start = libpf.Address(addr)
			if size, err := parseSysfsUint(mod, "coresize"); err == nil {
				m.end = m.start + libpf.Address(size)
			}
		}
	}

	// Require at least 16 bytes of BuildID to ensure there is enough entropy for a FileID.
	// 16 bytes could happen when --build-id=md5 is passed to `ld`. This would imply a custom
	// kernel.
	var err error
	m.buildID, err = pfelf.GetBuildIDFromNotesFile(notesFile)
	if err == nil && len(m.buildID) >= 16 {
		m.fileID = libpf.FileIDFromKernelBuildID(m.buildID)
	}
}

func (m *Module) finish() {
	m.names = bytes.Clone(m.names)
	m.symbols = slices.Clone(m.symbols)
	sort.Slice(m.symbols, func(i, j int) bool {
		return m.symbols[i].offset >= m.symbols[j].offset
	})

	// Synthesize fileID if it was not available via /sys
	if m.fileID.Compare(libpf.FileID{}) == 0 && len(m.symbols) > 0 {
		// Hash exports and their normalized addresses.
		h := fnv.New128a()

		h.Write(m.bytesAt(0)) // module name
		size := uint64(m.end - m.start)
		h.Write(libpf.SliceFrom(&size))

		for _, sym := range m.symbols {
			h.Write(m.bytesAt(sym.index))
			addr := uint64(sym.offset)
			h.Write(libpf.SliceFrom(&addr))
		}

		var hash [16]byte
		fileID, err := libpf.FileIDFromBytes(h.Sum(hash[:0]))
		if err != nil {
			panic("calcFallbackModuleID file ID construction is broken")
		}

		log.Debugf("Fallback module ID for module %s is '%s' (num syms: %d)",
			m.Name(), fileID.Base64(), len(m.symbols))
	}
}

func (m *Module) Name() string {
	return m.stringAt(0)
}

func (m *Module) Start() libpf.Address {
	return m.start
}

func (m *Module) End() libpf.Address {
	return m.end
}

func (m *Module) BuildID() string {
	return m.buildID
}

func (m *Module) FileID() libpf.FileID {
	return m.fileID
}

func (m *Module) LookupSymbolByAddress(pc libpf.Address) (funcName string, offset uint) {
	pcOffs := uint32(pc - m.start)
	symIdx := sort.Search(len(m.symbols), func(i int) bool {
		return pcOffs >= m.symbols[i].offset
	})
	if symIdx >= len(m.symbols) {
		return "", 0
	}
	sym := &m.symbols[symIdx]
	symName := m.stringAt(sym.index)
	return symName, uint(pcOffs - sym.offset)
}

func (m *Module) LookupSymbol(name string) (libpf.Address, error) {
	for _, sym := range m.symbols {
		if m.stringAt(sym.index) == name {
			return m.start + libpf.Address(sym.offset), nil
		}
	}
	return 0, ErrNoSymbol
}

func (m *Module) LookupSymbolsByPrefix(prefix string) []*libpf.Symbol {
	res := make([]*libpf.Symbol, 0, 8)
	for _, sym := range m.symbols {
		symName := m.stringAt(sym.index)
		if strings.HasPrefix(symName, prefix) {
			symAddr := m.start + libpf.Address(sym.offset)
			res = append(res, &libpf.Symbol{
				Name:    libpf.SymbolName(symName),
				Address: libpf.SymbolValue(symAddr),
			})
		}
	}
	return res
}

func (s *Symbolizer) updateSymbolsFrom(r io.Reader) error {
	var mod *Module
	var curName string

	s.valid.Store(true)
	noSymbols := true

	// Allocate buffers which should be able to hold the symbol data
	// from the vmlinux main image without resizing based on normal
	// distribution kernel (all modules are significantly smaller):
	// - about 200-300 modules
	// - 2.5MB for symbol names
	// - 100k symbols
	mods := make([]Module, 0, 400)
	names := make([]byte, 0, 3*1024*1024)
	syms := make([]symbol, 0, 128*1024)

	for scanner := bufio.NewScanner(r); scanner.Scan(); {
		// Avoid heap allocation by not using scanner.Text().
		// NOTE: The underlying bytes will change with the next call to scanner.Scan(),
		// so make sure to not keep any references after the end of the loop iteration.
		line := stringutil.ByteSlice2String(scanner.Bytes())

		// Avoid heap allocations here - do not use strings.FieldsN()
		var fields [4]string
		nFields := stringutil.FieldsN(line, fields[:])
		if nFields < 3 {
			return fmt.Errorf("unexpected line in kallsyms: '%s'", line)
		}

		// Skip non-text symbols, see 'man nm'.
		// Special case for 'etext', which can be of type `D` (data) in some kernels.
		if strings.IndexByte("TtVvWw", fields[1][0]) == -1 && fields[2] != "_etext" {
			continue
		}

		address, err := strconv.ParseUint(fields[0], 16, pointerBits)
		if err != nil {
			return fmt.Errorf("failed to parse address value: '%s'", fields[0])
		}
		if address != 0 {
			noSymbols = false
		}

		moduleName := Kernel
		if fields[3] != "" {
			moduleName = fields[3]
			if moduleName[0] != '[' && moduleName[len(moduleName)-1] != ']' {
				return fmt.Errorf("failed to parse module name: '%s'", moduleName)
			}
			moduleName = moduleName[1 : len(moduleName)-1]
		}

		if curName != moduleName {
			if curName == Kernel && noSymbols {
				return ErrSymbolPermissions
			}
			if mod != nil {
				mod.finish()
			}

			mod = s.getModuleByAddress(libpf.Address(address))
			mtime := getSysfsMtime(moduleName)
			if mod != nil && mod.Name() == moduleName && mod.mtime == mtime {
				mods = append(mods, *mod)
				curName = mod.Name()
				mod = nil
			} else {
				mods = append(mods, Module{
					start:   0,
					end:     ^libpf.Address(0),
					mtime:   mtime,
					symbols: syms[0:0],
					names:   names[0:0],
				})
				mod = &mods[len(mods)-1]
				mod.init(moduleName)
				curName = mod.Name()
			}
		}

		if mod == nil {
			continue
		}

		switch fields[2] {
		case "_stext", "_text":
			if mod.start == 0 {
				mod.start = libpf.Address(address)
			}
		case "_etext":
			if mod.end == ^libpf.Address(0) {
				mod.end = libpf.Address(address)
			}
		case "_sinittext", "_einittext":
		default:
			if mod.start == 0 {
				mod.start = libpf.Address(address)
			}
			if addr := libpf.Address(address); addr >= mod.start && addr < mod.end {
				// Add symbol to the module symbols
				mod.symbols = append(mod.symbols, symbol{
					offset: uint32(addr - mod.start),
					index:  mod.addName(fields[2]),
				})
			}
		}
	}
	if mod != nil {
		if mod.end == ^libpf.Address(0) && len(mod.symbols) > 0 {
			// Synthesize the end address at last symbol rounded up to page size
			// because it could not be reliably determined.
			lastSymbol := mod.start + libpf.Address(mod.symbols[len(mod.symbols)-1].offset)
			mod.end = (lastSymbol + 4095) & ^libpf.Address(4095)
		}
		mod.finish()
	}
	if noSymbols {
		return ErrSymbolPermissions
	}

	sort.Slice(mods, func(i, j int) bool {
		return mods[i].start >= mods[j].start
	})
	s.modules = slices.Clone(mods)
	return nil
}

func (s *Symbolizer) reload() error {
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return fmt.Errorf("unable to open %s: %v", kallsymsPath, err)
	}
	defer file.Close()

	return s.updateSymbolsFrom(file)
}

func (s *Symbolizer) Refresh() error {
	if !s.valid.Load() {
		if err := s.reload(); err != nil {
			s.valid.Store(false)
			return err
		}
	}
	return nil
}

func (s *Symbolizer) Invalidate() {
	s.valid.Store(false)
}

func (s *Symbolizer) getModuleByAddress(pc libpf.Address) *Module {
	modIdx := sort.Search(len(s.modules), func(i int) bool {
		return pc >= s.modules[i].start
	})
	if modIdx >= len(s.modules) {
		return nil
	}
	m := &s.modules[modIdx]
	if pc < m.start || pc >= m.end {
		return nil
	}
	return m
}

func (s *Symbolizer) GetModuleByAddress(pc libpf.Address) (*Module, error) {
	if err := s.Refresh(); err != nil {
		return nil, err
	}
	if mod := s.getModuleByAddress(pc); mod != nil {
		return mod, nil
	}
	return nil, ErrNoModule
}

func (s *Symbolizer) GetModuleByName(module string) (*Module, error) {
	if err := s.Refresh(); err != nil {
		return nil, err
	}
	for i := range s.modules {
		kmod := &s.modules[i]
		if kmod.Name() == module {
			return kmod, nil
		}
	}
	return nil, ErrNoModule
}

func (s *Symbolizer) LookupSymbol(module, name string) (libpf.Address, error) {
	mod, err := s.GetModuleByName(module)
	if err != nil {
		return 0, err
	}
	return mod.LookupSymbol(name)
}
