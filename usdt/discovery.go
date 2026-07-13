// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// Discover returns the USDT probes in an executable file-backed mapping.
// Results are cached by backing-file identity, including empty results.
func (d *Discoverer) Discover(
	pr process.Process,
	mapping *process.RawMapping,
) ([]AttachmentPoint, error) {
	if !mapping.IsExecutable() || mapping.IsAnonymous() {
		return nil, nil
	}

	fileID := mapping.GetOnDiskFileIdentifier()
	if cached, ok := d.parseCache.Get(fileID); ok {
		return cached, nil
	}

	// OpenELFMapping uses /proc/<pid>/map_files/<start>-<end>, so this also
	// works for deleted files and mappings in another mount namespace.
	ef, err := process.OpenELFMapping(pr, mapping)
	if err != nil {
		// Executable mappings are not necessarily ELF files. Cache expected
		// misses so they are not retried on every process synchronization.
		if errors.Is(err, process.ErrMappingFileUnavailable) || errors.Is(err, pfelf.ErrNotELF) {
			d.parseCache.Add(fileID, nil)
			return nil, nil
		}
		return nil, fmt.Errorf("open ELF mapping: %w", err)
	}
	defer ef.Close()

	notes, sectionBase, err := readSDTNotes(ef)
	if err != nil {
		return nil, fmt.Errorf("parse .note.stapsdt: %w", err)
	}

	points := make([]AttachmentPoint, 0, len(notes))
	for _, note := range notes {
		location, err := adjustedSDTAddress(sectionBase, note.base, note.location)
		if err != nil {
			return nil, fmt.Errorf("adjust %s:%s location: %w",
				note.provider, note.name, err)
		}
		location, err = elfFileOffset(ef, location, true)
		if err != nil {
			return nil, fmt.Errorf("resolve %s:%s location: %w",
				note.provider, note.name, err)
		}

		var semaphoreOffset uint64
		if note.semaphore != 0 {
			semaphore, err := adjustedSDTAddress(sectionBase, note.base, note.semaphore)
			if err != nil {
				return nil, fmt.Errorf("adjust %s:%s semaphore: %w",
					note.provider, note.name, err)
			}
			semaphoreOffset, err = elfFileOffset(ef, semaphore, false)
			if err != nil {
				return nil, fmt.Errorf("resolve %s:%s semaphore: %w",
					note.provider, note.name, err)
			}
		}

		points = append(points, AttachmentPoint{
			Provider:        note.provider,
			Name:            note.name,
			Location:        location,
			SemaphoreOffset: semaphoreOffset,
		})
	}

	d.parseCache.Add(fileID, points)
	return points, nil
}
