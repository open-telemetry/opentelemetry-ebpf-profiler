// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// Instance holds the set of live USDT attachments for one PID.
//
// Owned by ProcessManager and stored in its usdtInstances map. Lifetime is
// bounded by the process lifetime: created/extended in Reconcile and torn
// down in Detach from processPIDExit.
type Instance struct {
	pid libpf.PID

	// mu guards attached. ProcessManager.SynchronizeProcess calls Reconcile
	// without holding pm.mu, and ProcessManager.processPIDExit hands Detach
	// off to a separate background goroutine (also without pm.mu held). If
	// a process exits while a Reconcile for the same pid is still in
	// flight, both can reach the same Instance concurrently; without this
	// lock that is an unsynchronized concurrent map read/write on attached.
	mu sync.Mutex

	// attached is the source of truth for what is currently attached for
	// this pid. Keyed for O(1) diff against the desired set computed from
	// current mappings. Guarded by mu.
	attached map[ProbeKey]AttachedProbe
}

// desiredEntry pairs a parsed probe with the minimal mapping coordinates
// needed to (a) attach the uprobe and (b) build the /proc/<pid>/map_files
// path. We don't retain the full RawMapping because its Path field may
// point into a scanner buffer that gets recycled after IterateMappings'
// callback returns.
type desiredEntry struct {
	vaddr  uint64
	length uint64
	probe  parsedProbe
}

// NewInstance creates an empty Instance for the given PID. Callers should
// store the returned Instance in usdtInstances under pm.mu before calling
// Reconcile, so that concurrent reconcile paths share one object and
// serialize via Instance.mu.
func NewInstance(pid libpf.PID) *Instance {
	return &Instance{pid: pid, attached: make(map[ProbeKey]AttachedProbe)}
}

// NumAttached returns the number of currently attached probes for this
// instance. Used by periodic reconciliation to identify PIDs that need
// re-scanning.
func (inst *Instance) NumAttached() int {
	if inst == nil {
		return 0
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return len(inst.attached)
}

// HasProbeKind returns true if a probe of the given kind is currently attached.
func (inst *Instance) HasProbeKind(kind ProbeKind) bool {
	if inst == nil {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	for key := range inst.attached {
		if key.Kind == kind {
			return true
		}
	}
	return false
}

// Reconcile diffs the set of USDT probes desired for `pid` (derived by
// scanning the executable mappings) against what is currently attached on
// `inst`, attaches any newly-desired probes, and detaches any that are no
// longer present in the mapping set.
//
// Called from ProcessManager.SynchronizeProcess on every sync (not only on
// first sight) so that probes inside libraries dlopen'd after process start
// are eventually picked up.
//
// If `inst` is nil a new Instance is created. The returned Instance should
// always be stored back into ProcessManager.usdtInstances[pid] (replacing
// any previous value), even on partial failure.
func (m *Manager) Reconcile(
	pid libpf.PID,
	pr process.Process,
	inst *Instance,
) (*Instance, error) {
	if inst == nil {
		inst = NewInstance(pid)
	}

	// Build the desired set by scanning every executable file-backed
	// mapping. We process inline in the callback so that RawMapping.Path
	// and similar buffer-backed fields don't escape their lifetime; even
	// though scanMapping doesn't currently need Path, this keeps the
	// invariant tight.
	desired := make(map[ProbeKey]desiredEntry)
	var scanErrs []error
	_, iterErr := pr.IterateMappings(func(rm process.RawMapping) bool {
		if !rm.IsExecutable() || rm.IsAnonymous() {
			return true
		}
		probes, err := m.scanMapping(pr, &rm)
		if err != nil {
			scanErrs = append(scanErrs,
				fmt.Errorf("scan mapping %#x-%#x: %w",
					rm.Vaddr, rm.Vaddr+rm.Length, err))
			return true
		}
		if len(probes) == 0 {
			return true
		}
		fileID := rm.GetOnDiskFileIdentifier()
		for _, p := range probes {
			key := ProbeKey{
				PID:    pid,
				FileID: fileID,
				Kind:   p.Kind,
				Offset: p.Location,
			}
			desired[key] = desiredEntry{
				vaddr:  rm.Vaddr,
				length: rm.Length,
				probe:  p,
			}
		}
		return true
	})
	if iterErr != nil && !errors.Is(iterErr, process.ErrCallbackStopped) {
		// Mapping iteration failed before we built the full desired set.
		// Don't detach anything based on a partial view; just report.
		scanErrs = append(scanErrs, fmt.Errorf("iterate mappings: %w", iterErr))
		return inst, errors.Join(scanErrs...)
	}

	// Lock for the actual diff/attach/detach against inst.attached. Mapping
	// scans above run unlocked since they don't touch inst; this keeps the
	// lock held only around the section that races with a concurrent Detach
	// (see Instance.mu).
	inst.mu.Lock()
	defer inst.mu.Unlock()

	// Detach first: bounds peak live link count and lets a replaced
	// library re-attach to its new inode without colliding.
	var detachErrs []error
	numDetached := 0
	for key, ap := range inst.attached {
		if _, keep := desired[key]; keep {
			continue
		}
		if err := ap.Link.Close(); err != nil {
			detachErrs = append(detachErrs,
				fmt.Errorf("detach %v: %w", key, err))
		}
		delete(inst.attached, key)
		numDetached++
	}

	// Attach newly-desired probes. Per-probe failures are accumulated and
	// returned but do not abort the loop; partial success is the design.
	var attachErrs []error
	numAttached := 0
	for key, de := range desired {
		if _, already := inst.attached[key]; already {
			continue
		}
		mapping := &process.RawMapping{
			Vaddr:  de.vaddr,
			Length: de.length,
		}
		lnk, err := m.attach(pid, mapping, de.probe)
		if err != nil {
			if errors.Is(err, errProgramNotLoaded) {
				// Kind has no registered program; not an error worth
				// surfacing on every reconcile. Skip quietly.
				continue
			}
			attachErrs = append(attachErrs,
				fmt.Errorf("attach %v: %w", key, err))
			continue
		}
		inst.attached[key] = AttachedProbe{Key: key, Link: lnk}
		numAttached++
	}

	if numAttached > 0 || numDetached > 0 {
		log.Debugf("USDT pid=%d live=%d (+%d,-%d)",
			pid, len(inst.attached), numAttached, numDetached)
	}

	allErrs := append(append(scanErrs, detachErrs...), attachErrs...)
	return inst, errors.Join(allErrs...)
}

// Detach closes every live attachment for this pid. Called from
// ProcessManager.processPIDExit (via a goroutine, so it runs without
// pm.mu held).
func (inst *Instance) Detach() error {
	if inst == nil {
		return nil
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	var errs []error
	for key, ap := range inst.attached {
		if err := ap.Link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %v: %w", key, err))
		}
		delete(inst.attached, key)
	}
	return errors.Join(errs...)
}
