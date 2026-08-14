// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"debug/elf"
	"errors"
	"fmt"

	parcausdt "github.com/parca-dev/usdt"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// scanMapping returns the list of USDT probes we care about within one
// memory mapping's backing file.
//
// Results are cached on the Manager by OnDiskFileIdentifier, so each
// distinct binary/library is parsed at most once across the lifetime of
// the profiler. This matters because the same .so is typically mapped by
// many processes.
//
// A non-nil error means the file could not be opened or parsed; the caller
// (Reconcile) treats those as soft failures and continues with other
// mappings. A nil-error empty slice means "this binary has no probes we
// want" and is cached so we won't re-parse it.
func (m *Manager) scanMapping(
	pr process.Process,
	mapping *process.RawMapping,
) ([]parsedProbe, error) {
	fileID := mapping.GetOnDiskFileIdentifier()

	if cached, ok := m.parseCache.Get(fileID); ok {
		return cached, nil
	}

	// OpenELFMapping opens the mapping via /proc/<pid>/map_files/<s>-<e>,
	// so it works for deleted-on-disk binaries and respects the target
	// process's mount namespace.
	ef, err := process.OpenELFMapping(pr, mapping)
	if err != nil {
		// ErrMappingFileUnavailable / non-ELF: cache empty so we don't
		// retry on every Reconcile. Not every executable file-backed mapping is
		// an ELF object (for example memfd/JIT/runtime-generated mappings), so
		// non-ELF mappings are expected while scanning for heap USDT notes.
		if errors.Is(err, process.ErrMappingFileUnavailable) || errors.Is(err, pfelf.ErrNotELF) {
			m.parseCache.Add(fileID, nil)
			return nil, nil
		}
		return nil, fmt.Errorf("open ELF mapping: %w", err)
	}
	defer ef.Close()

	probes, err := parcausdt.ParseProbes(&pfelfReader{f: ef})
	if err != nil {
		return nil, fmt.Errorf("parse .note.stapsdt: %w", err)
	}

	// Filter to the provider we care about and translate names to ProbeKind.
	var out []parsedProbe
	for i := range probes {
		p := &probes[i]
		if p.Provider != ProbeProvider {
			continue
		}
		kind := probeKindFromName(p.Name)
		if kind == ProbeUnknown {
			continue
		}
		out = append(out, parsedProbe{
			Kind:            kind,
			Location:        p.Location,
			SemaphoreOffset: p.SemaphoreOffset,
		})
	}

	// Cache even empty results so probe-less binaries aren't re-parsed.
	m.parseCache.Add(fileID, out)
	return out, nil
}

// probeKindFromName maps a USDT probe name to a ProbeKind. Provider is
// assumed to already have been filtered to ProbeProvider.
func probeKindFromName(name string) ProbeKind {
	switch name {
	case "alloc":
		return ProbeHeapAlloc
	case "free":
		return ProbeHeapFree
	// TODO: "mmap", "munmap" once defined upstream
	default:
		return ProbeUnknown
	}
}

// pfelfReader adapts *pfelf.File to parcausdt.ELFReader. Only `.note.stapsdt`
// and `.stapsdt.base` need section data populated; other sections are
// reported by name+addr only.
type pfelfReader struct {
	f *pfelf.File
}

func (r *pfelfReader) Sections() ([]parcausdt.ELFSection, error) {
	if err := r.f.LoadSections(); err != nil {
		return nil, err
	}
	out := make([]parcausdt.ELFSection, 0, len(r.f.Sections))
	for i := range r.f.Sections {
		s := &r.f.Sections[i]
		sec := parcausdt.ELFSection{
			Name: s.Name,
			Addr: s.Addr,
		}
		if s.Name == ".note.stapsdt" || s.Name == ".stapsdt.base" {
			data, err := s.Data(uint(s.Size))
			if err != nil {
				return nil, fmt.Errorf("read section %s: %w", s.Name, err)
			}
			sec.Data = data
		}
		out = append(out, sec)
	}
	return out, nil
}

func (r *pfelfReader) LoadSegments() []parcausdt.ELFProg {
	var out []parcausdt.ELFProg
	for i := range r.f.Progs {
		p := &r.f.Progs[i]
		if p.Type != elf.PT_LOAD {
			continue
		}
		out = append(out, parcausdt.ELFProg{
			Vaddr: p.Vaddr,
			Memsz: p.Memsz,
			Off:   p.Off,
		})
	}
	return out
}
