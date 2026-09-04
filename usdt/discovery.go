// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"errors"
	"fmt"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Discover returns the USDT attachment points for an ELF file identified by
// fileID. The ELF is opened lazily via ref, so a cache hit avoids any I/O.
// If individual notes cannot be resolved, it returns the valid points together
// with an error describing the skipped notes. Results are cached by
// backing-file identity, including empty and partial results.
func (d *Discoverer) Discover(
	ref *pfelf.Reference,
	fileID util.OnDiskFileIdentifier,
) ([]AttachmentPoint, error) {
	if cached, ok := d.parseCache.Get(fileID); ok {
		return slices.Clone(cached), nil
	}

	ef, err := ref.GetELF()
	if err != nil {
		// The backing file may not be an ELF. Cache expected misses so
		// they are not retried on every process synchronization.
		if errors.Is(err, pfelf.ErrNotELF) {
			d.parseCache.Add(fileID, nil)
			return nil, nil
		}
		return nil, fmt.Errorf("open ELF: %v", err)
	}

	notes, sectionBase, err := readSDTNotes(ef)
	if err != nil {
		// Structural note errors are deterministic for this backing file.
		d.parseCache.Add(fileID, nil)
		return nil, fmt.Errorf("parse .note.stapsdt: %v", err)
	}

	points, discoveryErr := attachmentPointsFromNotes(ef, sectionBase, notes)
	d.parseCache.Add(fileID, points)
	return slices.Clone(points), discoveryErr
}

func attachmentPointsFromNotes(
	f *pfelf.File,
	sectionBase uint64,
	notes []sdtNote,
) ([]AttachmentPoint, error) {
	points := make([]AttachmentPoint, 0, len(notes))
	var discoveryErrs []error
	for _, note := range notes {
		location, err := adjustedSDTAddress(sectionBase, note.base, note.location)
		if err != nil {
			discoveryErrs = append(discoveryErrs, fmt.Errorf("adjust %s:%s location: %v",
				note.provider, note.name, err))
			continue
		}
		location, err = elfFileOffset(f, location, true)
		if err != nil {
			discoveryErrs = append(discoveryErrs, fmt.Errorf("resolve %s:%s location: %v",
				note.provider, note.name, err))
			continue
		}

		var semaphoreOffset uint64
		if note.semaphore != 0 {
			semaphore, err := adjustedSDTAddress(sectionBase, note.base, note.semaphore)
			if err != nil {
				discoveryErrs = append(discoveryErrs, fmt.Errorf(
					"adjust %s:%s semaphore: %v", note.provider, note.name, err))
				continue
			}
			semaphoreOffset, err = elfFileOffset(f, semaphore, false)
			if err != nil {
				discoveryErrs = append(discoveryErrs, fmt.Errorf(
					"resolve %s:%s semaphore: %v", note.provider, note.name, err))
				continue
			}
		}

		points = append(points, AttachmentPoint{
			Provider:        note.provider,
			Name:            note.name,
			Location:        location,
			SemaphoreOffset: semaphoreOffset,
		})
	}
	return points, errors.Join(discoveryErrs...)
}
