// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"maps"
	"sync"
)

// PIDFilter is a read-only view of a set of PIDs used for filtering.
// Consumers that only need to read the current PID set accept this interface.
type PIDFilter interface {
	Snapshot() map[PID]bool
}

// MutablePIDFilter extends PIDFilter with the ability to update the set
// and subscribe to changes. Only the top-level writer should hold this.
type MutablePIDFilter interface {
	PIDFilter
	Update(newPids map[PID]bool)
	OnChange(fn func(map[PID]bool))
}

// ApplyFilterOnChange initializes a consumer from filter and subscribes to
// future updates. It calls fn immediately with the current snapshot, and if
// filter is a MutablePIDFilter, registers fn as an OnChange listener.
func ApplyFilterOnChange(filter PIDFilter, fn func(map[PID]bool)) {
	fn(filter.Snapshot())
	if mf, ok := filter.(MutablePIDFilter); ok {
		mf.OnChange(fn)
	}
}

// livePIDSet is the concrete thread-safe implementation of MutablePIDFilter.
type livePIDSet struct {
	mu       sync.RWMutex
	pids     map[PID]bool
	onChange []func(map[PID]bool)
}

var _ MutablePIDFilter = (*livePIDSet)(nil)

// NewMutablePIDFilter creates a new MutablePIDFilter with the given initial PIDs.
func NewMutablePIDFilter(initial map[PID]bool) MutablePIDFilter {
	if initial == nil {
		initial = make(map[PID]bool)
	}
	return &livePIDSet{pids: initial}
}

// Snapshot returns a shallow copy of the current PID set.
func (s *livePIDSet) Snapshot() map[PID]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[PID]bool, len(s.pids))
	for k, v := range s.pids {
		cp[k] = v
	}
	return cp
}

// OnChange registers a callback that fires when the PID set actually
// changes via Update(). If Update() is called with the same PIDs, the
// callback is not invoked. Callbacks are invoked outside the lock.
func (s *livePIDSet) OnChange(fn func(map[PID]bool)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, fn)
	s.mu.Unlock()
}

// Update atomically replaces the PID set and notifies all subscribers.
// If the new PID set is equal to the current set, no notification is sent.
// Callbacks are invoked with the new PID set, outside the lock.
func (s *livePIDSet) Update(newPids map[PID]bool) {
	if newPids == nil {
		newPids = make(map[PID]bool)
	}
	s.mu.Lock()

	if maps.Equal(s.pids, newPids) {
		s.mu.Unlock()
		return
	}

	s.pids = newPids
	listeners := make([]func(map[PID]bool), len(s.onChange))
	copy(listeners, s.onChange)
	s.mu.Unlock()

	for _, fn := range listeners {
		fn(newPids)
	}
}
