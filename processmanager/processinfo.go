// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

// This file is the only place that should access pidToProcessInfo.
// The map is used to synchronize state between eBPF maps and process
// manager. The access needs to stay here so the interaction between
// these two components can be audited to be consistent.

// The public functions in this file are restricted to be used from the
// HA/tracer and tools/coredump modules only.

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/proc"
	"go.opentelemetry.io/ebpf-profiler/process"
	eim "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// assignTSDInfo updates the TSDInfo for the Interpreters on given PID.
// Caller must hold pm.mu write lock.
func (pm *ProcessManager) assignTSDInfo(pid libpf.PID, tsdInfo *tpbase.TSDInfo) {
	if tsdInfo == nil {
		return
	}

	info, ok := pm.pidToProcessInfo[pid]
	if !ok {
		// This is guaranteed not to happen since assignTSDInfo is always called after
		// pm.updatePidInformation - but to avoid a possible panic we just return here.
		return
	} else if info.tsdInfo != nil {
		return
	}

	info.tsdInfo = tsdInfo

	// Update the tsdInfo to interpreters that are already attached
	for _, instance := range pm.interpreters[pid] {
		if err := instance.UpdateTSDInfo(pm.ebpf, pid, *tsdInfo); err != nil {
			log.Errorf("Failed to update PID %v TSDInfo: %v",
				pid, err)
		}
	}
}

// getTSDInfo retrieves the TSDInfo of given PID
// Caller must hold pm.mu read lock.
func (pm *ProcessManager) getTSDInfo(pid libpf.PID) *tpbase.TSDInfo {
	if info, ok := pm.pidToProcessInfo[pid]; ok {
		return info.tsdInfo
	}
	return nil
}

// updatePidInformation updates pidToProcessInfo with the new information about
// vaddr, offset, fileID and length for the given pid. If we don't know about the pid yet, it also
// allocates the embedded map. If the mapping for pid at vaddr with requestedLength and fileID
// already exists, it returns true. Otherwise false or an error.
//
// Caller must hold pm.mu write lock.
func (pm *ProcessManager) updatePidInformation(pid libpf.PID, m *Mapping) (bool, error) {
	info, ok := pm.pidToProcessInfo[pid]
	if !ok {
		// We don't have information for this pid, so we first need to
		// allocate the embedded map for this process.
		var processName string
		exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if name, err := os.ReadFile(fmt.Sprintf("/prod/%d/comm", pid)); err == nil {
			processName = string(name)
		}

		envVarMap := make(map[string]string, len(pm.includeEnvVars))
		if len(pm.includeEnvVars) > 0 {
			if envVars, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
				// environ has environment variables separated by a null byte (hex: 00)
				splittedVars := strings.Split(string(envVars), "\000")
				for _, envVar := range splittedVars {
					keyValuePair := strings.SplitN(envVar, "=", 2)

					// If the entry could not be split at a '=', ignore it
					// (last entry of environ might be empty)
					if len(keyValuePair) != 2 {
						continue
					}

					if _, ok := pm.includeEnvVars[keyValuePair[0]]; ok {
						envVarMap[keyValuePair[0]] = keyValuePair[1]
					}
				}
			}
		}

		info = &processInfo{
			meta: ProcessMeta{
				Name:         processName,
				Executable:   exePath,
				EnvVariables: envVarMap},
			mappings:         make(map[libpf.Address]*Mapping),
			mappingsByFileID: make(map[host.FileID]map[libpf.Address]*Mapping),
			tsdInfo:          nil,
		}
		pm.pidToProcessInfo[pid] = info

		// Insert a dummy page into the eBPF map pid_page_to_mapping_info that provides the eBPF
		// a quick way to check if we know something about this particular process.
		if err := pm.ebpf.UpdatePidPageMappingInfo(pid, dummyPrefix, 0, 0); err != nil {
			return false, fmt.Errorf(
				"failed to update pid_page_to_mapping_info dummy entry for PID %d: %v",
				pid, err)
		}
		pm.pidPageToMappingInfoSize++
	} else if mf, ok := info.mappings[m.Vaddr]; ok {
		if *m == *mf {
			// We try to update our information about a particular mapping we already know about.
			return true, nil
		}
	}

	info.addMapping(*m)

	prefixes, err := lpm.CalculatePrefixList(uint64(m.Vaddr), uint64(m.Vaddr)+m.Length)
	if err != nil {
		return false, fmt.Errorf("failed to create LPM entries for PID %d: %v", pid, err)
	}
	numUpdates := uint64(0)
	for _, prefix := range prefixes {
		if err = pm.ebpf.UpdatePidPageMappingInfo(pid, prefix, uint64(m.FileID),
			m.Bias); err != nil {
			err = fmt.Errorf(
				"failed to update pid_page_to_mapping_info (pid: %d, page: 0x%x/%d): %v",
				pid, prefix.Key, prefix.Length, err)
			break
		}
		numUpdates++
	}

	pm.pidPageToMappingInfoSize += numUpdates

	return false, err
}

// deletePIDAddress removes the mapping at addr from pid from the internal structure of the
// process manager instance as well as from the eBPF maps.
// Caller must hold pm.mu write lock.
func (pm *ProcessManager) deletePIDAddress(pid libpf.PID, addr libpf.Address) error {
	info, ok := pm.pidToProcessInfo[pid]
	if !ok {
		return fmt.Errorf("unknown PID %d: %w", pid, errUnknownPID)
	}

	mapping, ok := info.mappings[addr]
	if !ok {
		return fmt.Errorf("unknown memory mapping for PID %d at 0x%x: %w",
			pid, addr, errUnknownMapping)
	}

	prefixes, err := lpm.CalculatePrefixList(uint64(addr), uint64(addr)+mapping.Length)
	if err != nil {
		return fmt.Errorf("failed to create LPM entries for PID %d: %v", pid, err)
	}

	deleted, err := pm.ebpf.DeletePidPageMappingInfo(pid, prefixes)
	if err != nil {
		log.Errorf("Failed to delete mappings for PID %d: %v", pid, err)
	}

	pm.pidPageToMappingInfoSize -= uint64(deleted)
	info.removeMapping(mapping)

	return pm.eim.RemoveOrDecRef(mapping.FileID)
}

// assignInterpreter will update the interpreters maps with given interpreter.Instance.
func (pm *ProcessManager) assignInterpreter(pid libpf.PID, key util.OnDiskFileIdentifier,
	instance interpreter.Instance) {
	if _, ok := pm.interpreters[pid]; !ok {
		// This is the very first interpreter entry for this process.
		// So we need to initialize the structure first.
		pm.interpreters[pid] = make(map[util.OnDiskFileIdentifier]interpreter.Instance)
	}
	pm.interpreters[pid][key] = instance
}

// handleNewInterpreter is called to process new executable memory mappings. It uses the
// process manager to attach to the process/memory mapping if it is discovered that the
// memory mapping corresponds with an interpreter.
//
// It is important to note that this function may spawn a new goroutine in order to retry
// attaching to the interpreter, if the first attach attempt fails. In this case, `nil` will still
// be returned and thus a `nil` return value does not mean the attach was successful. It means
// that the attach was successful OR a retry is underway.
//
// The caller is responsible to hold the ProcessManager lock to avoid race conditions.
func (pm *ProcessManager) handleNewInterpreter(pr process.Process, m *Mapping,
	ei *eim.ExecutableInfo) error {
	// The same interpreter can be found multiple times under various different
	// circumstances. Check if this is already handled.
	pid := pr.PID()
	key := m.GetOnDiskFileIdentifier()
	if _, ok := pm.interpreters[pid]; ok {
		if _, ok := pm.interpreters[pid][key]; ok {
			return nil
		}
	}
	// Slow path: Interpreter detection or attachment needed
	instance, err := ei.Data.Attach(pm.ebpf, pid, libpf.Address(m.Bias), pr.GetRemoteMemory())
	if err != nil {
		return fmt.Errorf("failed to attach to %v in PID %v: %w",
			ei.Data, pid, err)
	}

	log.Debugf("Attached to %v interpreter in PID %v", ei.Data, pid)
	pm.assignInterpreter(pid, key, instance)

	if tsdInfo := pm.getTSDInfo(pid); tsdInfo != nil {
		err = instance.UpdateTSDInfo(pm.ebpf, pid, *tsdInfo)
		if err != nil {
			log.Errorf("Failed to update PID %v TSDInfo: %v", pid, err)
		}
	}

	return nil
}

// handleNewMapping processes new file backed mappings
func (pm *ProcessManager) handleNewMapping(pr process.Process, m *Mapping,
	elfRef *pfelf.Reference) error {
	// Resolve executable info first
	ei, err := pm.eim.AddOrIncRef(m.FileID, elfRef)
	if err != nil {
		return err
	}

	pid := pr.PID()

	// We intentionally don't take the lock immediately when entering this function and instead
	// rely on EIM's internal locking for the `AddOrIncRef` call. The reasoning here is that
	// the `AddOrIncRef` call can take a while, and we don't want to block the whole PM for that.
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Update the eBPF maps with information about this mapping.
	_, err = pm.updatePidInformation(pid, m)
	if err != nil {
		return err
	}

	pm.assignTSDInfo(pid, ei.TSDInfo)

	if ei.Data != nil {
		return pm.handleNewInterpreter(pr, m, &ei)
	}

	return nil
}

func (pm *ProcessManager) getELFInfo(pr process.Process, mapping *process.Mapping,
	elfRef *pfelf.Reference) elfInfo {
	key := mapping.GetOnDiskFileIdentifier()
	lastModified := pr.GetMappingFileLastModified(mapping)
	if info, ok := pm.elfInfoCache.Get(key); ok && info.lastModified == lastModified {
		// Cached data ok
		pm.elfInfoCacheHit.Add(1)
		return info
	}

	// Slow path, calculate all the data and update cache
	pm.elfInfoCacheMiss.Add(1)

	info := elfInfo{
		lastModified: lastModified,
	}

	var fileID libpf.FileID
	ef, err := elfRef.GetELF()
	if err == nil {
		fileID, err = pr.CalculateMappingFileID(mapping)
	}
	if err != nil {
		info.err = err
		// It is possible that the process has exited, and the mapping
		// file cannot be opened. Do not cache these errors.
		if !errors.Is(err, os.ErrNotExist) {
			// Cache the other errors: not an ELF, ELF corrupt, etc.
			// to reduce opening it again and again.
			pm.elfInfoCache.Add(key, info)
		}
		return info
	}

	hostFileID := host.FileIDFromLibpf(fileID)
	info.fileID = hostFileID
	info.addressMapper = ef.GetAddressMapper()
	if mapping.IsVDSO() {
		intervals := createVDSOSyntheticRecord(ef)
		if intervals.Deltas != nil {
			if err := pm.AddSynthIntervalData(hostFileID, intervals); err != nil {
				info.err = fmt.Errorf("failed to add synthetic deltas: %w", err)
			}
		}
	}
	// Do not cache the entry if synthetic stack delta loading failed,
	// so next encounter of the VDSO will retry loading them.
	if info.err == nil {
		pm.elfInfoCache.Add(key, info)
	}
	pm.FileIDMapper.Set(hostFileID, fileID)

	if pm.reporter.ExecutableKnown(fileID) {
		return info
	}

	baseName := path.Base(mapping.Path)
	if baseName == "/" {
		// There are circumstances where there is no filename.
		// E.g. kernel module 'bpfilter_umh' before Linux 5.9-rc1 uses
		// fork_usermode_blob() and launches process with a blob without
		// filename mapped in as the executable.
		baseName = "<anonymous-blob>"
	}

	gnuBuildID, _ := ef.GetBuildID()
	mapping2 := *mapping // copy to avoid races if callee saves the closure
	open := func() (process.ReadAtCloser, error) {
		return pr.OpenMappingFile(&mapping2)
	}
	pm.reporter.ExecutableMetadata(&reporter.ExecutableMetadataArgs{
		FileID:            fileID,
		FileName:          baseName,
		GnuBuildID:        gnuBuildID,
		DebuglinkFileName: ef.DebuglinkFileName(elfRef.FileName(), elfRef),
		Interp:            libpf.Native,
		Open:              open,
	})
	return info
}

// processNewExecMapping is the logic to add a new process.Mapping to processmanager.
func (pm *ProcessManager) processNewExecMapping(pr process.Process, mapping *process.Mapping) {
	// Filter uninteresting mappings
	if mapping.Inode == 0 && !mapping.IsVDSO() {
		return
	}

	// Create a Reference so we don't need to open the ELF multiple times
	elfRef := pfelf.NewReference(mapping.Path, pr)
	defer elfRef.Close()

	info := pm.getELFInfo(pr, mapping, elfRef)
	if info.err != nil {
		// Unable to get the information. Most likely cause is that the
		// process has exited already and the mapping file is unavailable
		// or it is not an ELF file. Ignore these errors silently.
		if !errors.Is(info.err, os.ErrNotExist) && !errors.Is(info.err, pfelf.ErrNotELF) {
			log.Debugf("Failed to get ELF info for PID %d file %v: %v",
				pr.PID(), mapping.Path, info.err)
		}
		return
	}

	// Get the virtual addresses for this mapping
	elfSpaceVA, ok := info.addressMapper.FileOffsetToVirtualAddress(mapping.FileOffset)
	if !ok {
		log.Debugf("Failed to map file offset of PID %d, file %s, offset %d",
			pr.PID(), mapping.Path, mapping.FileOffset)
		return
	}

	if err := pm.handleNewMapping(pr,
		&Mapping{
			FileID:     info.fileID,
			Vaddr:      libpf.Address(mapping.Vaddr),
			Bias:       mapping.Vaddr - elfSpaceVA,
			Length:     mapping.Length,
			Device:     mapping.Device,
			Inode:      mapping.Inode,
			FileOffset: mapping.FileOffset,
		}, elfRef); err != nil {
		// Same as above, ignore the errors related to process having exited.
		// Also ignore errors of deferred file IDs.
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, eim.ErrDeferredFileID) {
			log.Errorf("Failed to handle mapping for PID %d, file %s: %v",
				pr.PID(), mapping.Path, err)
		}
	}
}

// processRemovedMappings removes listed memory mappings and loaded interpreters from
// the internal structures and eBPF maps.
func (pm *ProcessManager) processRemovedMappings(pid libpf.PID, mappings []libpf.Address,
	interpretersValid libpf.Set[util.OnDiskFileIdentifier]) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, addr := range mappings {
		if err := pm.deletePIDAddress(pid, addr); err != nil {
			log.Debugf("Failed to handle native unmapping of 0x%x in PID %d: %v",
				addr, pid, err)
		}
	}

	if !pm.interpreterTracerEnabled {
		return
	}

	if _, ok := pm.interpreters[pid]; !ok {
		log.Debugf("ProcessManager doesn't know about PID %d", pid)
		return
	}

	for key, instance := range pm.interpreters[pid] {
		if _, ok := interpretersValid[key]; ok {
			continue
		}
		if err := instance.Detach(pm.ebpf, pid); err != nil {
			log.Errorf("Failed to unload interpreter for PID %d: %v",
				pid, err)
		}
		delete(pm.interpreters[pid], key)
	}

	if len(pm.interpreters[pid]) == 0 {
		// There are no longer any mapped interpreters in the process, therefore we can
		// remove the entry.
		delete(pm.interpreters, pid)
	}
}

// synchronizeMappings synchronizes executable mappings for the given PID.
// This method will be called when a PID is first encountered or when the eBPF
// code encounters an address in an executable mapping that HA has no information
// on. Therefore, executable mapping synchronization takes place lazily on-demand,
// and map/unmap operations are not precisely tracked (reduce processing load).
// This means that at any point, we may have cached stale (or miss) executable
// mappings. The expectation is that stale mappings will disappear and new
// mappings cached at the next synchronization triggered by process exit or
// unknown address encountered.
//
// TODO: Periodic synchronization of mappings for every tracked PID.
func (pm *ProcessManager) synchronizeMappings(pr process.Process,
	mappings []process.Mapping) bool {
	newProcess := true
	pid := pr.PID()
	mpAdd := make(map[libpf.Address]*process.Mapping, len(mappings))
	mpRemove := make([]libpf.Address, 0)

	interpretersValid := make(libpf.Set[util.OnDiskFileIdentifier])
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || m.IsAnonymous() {
			continue
		}
		mpAdd[libpf.Address(m.Vaddr)] = m
		key := m.GetOnDiskFileIdentifier()
		interpretersValid[key] = libpf.Void{}
	}

	// Generate the list of added and removed mappings.
	pm.mu.RLock()
	if info, ok := pm.pidToProcessInfo[pid]; ok {
		// Iterate over cached executable mappings, if any, and collect mappings
		// that have changed so that they are later batch-removed.
		for addr, existingMapping := range info.mappings {
			if newMapping, ok := mpAdd[addr]; ok {
				// Check the relevant fields to see if it's still the same
				if newMapping.Device == existingMapping.Device &&
					newMapping.Inode == existingMapping.Inode &&
					newMapping.FileOffset == existingMapping.FileOffset &&
					newMapping.Length == existingMapping.Length {
					// Mapping hasn't changed, remove from the new set
					delete(mpAdd, addr)
					continue
				}
			}
			// Mapping has changed
			mpRemove = append(mpRemove, addr)
		}
		newProcess = false
	}
	pm.mu.RUnlock()

	// First, remove mappings that have changed
	pm.processRemovedMappings(pid, mpRemove, interpretersValid)

	// Add the new ELF mappings
	for _, mapping := range mpAdd {
		pm.processNewExecMapping(pr, mapping)
	}

	// Update interpreter plugins about the changed mappings
	if pm.interpreterTracerEnabled {
		pm.mu.Lock()
		for _, instance := range pm.interpreters[pid] {
			err := instance.SynchronizeMappings(pm.ebpf, pm.reporter, pr, mappings)
			if err != nil {
				if alive, _ := proc.IsPIDLive(pid); alive {
					log.Errorf("Failed to handle new anonymous mapping for PID %d: %v", pid, err)
				} else {
					log.Debugf("Failed to handle new anonymous mapping for PID %d: process exited",
						pid)
				}
			}
		}
		pm.mu.Unlock()
	}

	if len(mpAdd) > 0 || len(mpRemove) > 0 {
		log.Debugf("Added %v mappings, removed %v mappings for PID: %v",
			len(mpAdd), len(mpRemove), pid)
	}
	return newProcess
}

// processPIDExit informs the ProcessManager that a process exited and no longer will be scheduled.
// exitKTime is stored for later processing in ProcessedUntil, when traces up to this time have been
// processed. There can be a race condition if we can not clean up the references for this process
// fast enough and this particular pid is reused again by the system.
func (pm *ProcessManager) processPIDExit(pid libpf.PID) {
	exitKTime := times.GetKTime()
	log.Debugf("- PID: %v", pid)

	var err error
	defer func() {
		if err != nil {
			log.Error(err)
		}
	}()
	defer pm.ebpf.RemoveReportedPID(pid)
	pm.mu.Lock()
	defer pm.mu.Unlock()

	info, pidExists := pm.pidToProcessInfo[pid]
	if !pidExists {
		log.Debugf("Skip process exit handling for unknown PID %d", pid)
		return
	}

	// ProcessPIDExit may be called multiple times in short succession
	// for the same PID, don't update exitKTime if we've previously recorded it.
	if _, pidExitProcessed := pm.exitEvents[pid]; !pidExitProcessed {
		pm.exitEvents[pid] = exitKTime
	} else {
		log.Debugf("Skip duplicate process exit handling for PID %d", pid)
		return
	}

	// Delete all entries we have for this particular PID from pid_page_to_mapping_info.
	deleted, err2 := pm.ebpf.DeletePidPageMappingInfo(pid, []lpm.Prefix{dummyPrefix})
	if err2 != nil {
		err = errors.Join(err, fmt.Errorf("failed to delete dummy prefix for PID %d: %v",
			pid, err2))
	}
	pm.pidPageToMappingInfoSize -= uint64(deleted)

	for address := range info.mappings {
		if err2 = pm.deletePIDAddress(pid, address); err2 != nil {
			err = errors.Join(err, fmt.Errorf("failed to delete address %#x for PID %d: %v",
				address, pid, err2))
		}
	}
}

// SynchronizeProcess triggers ProcessManager to update its internal information
// about a process. This includes process exit information as well as changed memory mappings.
func (pm *ProcessManager) SynchronizeProcess(pr process.Process) {
	pid := pr.PID()
	log.Debugf("= PID: %v", pid)

	// Abort early if process is waiting for cleanup in ProcessedUntil
	pm.mu.Lock()
	_, ok := pm.exitEvents[pid]
	pm.mu.Unlock()

	if ok {
		log.Debugf("PID %v waiting for cleanup, aborting SynchronizeProcess", pid)
		pm.ebpf.RemoveReportedPID(pid)
		return
	}

	pm.mappingStats.numProcAttempts.Add(1)
	start := time.Now()
	mappings, numParseErrors, err := pr.GetMappings()
	elapsed := time.Since(start)
	pm.mappingStats.numProcParseErrors.Add(numParseErrors)

	if err != nil {
		if os.IsPermission(err) {
			// Ignore the synchronization completely in case of permission
			// error. This implies the process is still alive, but we cannot
			// inspect it. Exiting here keeps the PID in the eBPF maps so
			// we avoid a notification flood to resynchronize.
			pm.mappingStats.errProcPerm.Add(1)
			return
		}

		// All other errors imply that the process has exited.
		// Clean up, and notify eBPF.
		pm.processPIDExit(pid)
		if os.IsNotExist(err) {
			// Since listing /proc and opening files in there later is inherently racy,
			// we expect to lose the race sometimes and thus expect to hit os.IsNotExist.
			pm.mappingStats.errProcNotExist.Add(1)
		} else if e, ok := err.(*os.PathError); ok && e.Err == syscall.ESRCH {
			// If the process exits while reading its /proc/$PID/maps, the kernel will
			// return ESRCH. Handle it as if the process did not exist.
			pm.mappingStats.errProcESRCH.Add(1)
		}
		return
	}
	if len(mappings) == 0 {
		// Valid process without any (executable) mappings. All cases are
		// handled as process exit. Possible causes and reasoning:
		// 1. It is a kernel worker process. The eBPF does not send events from these,
		//    but we can see kernel threads here during startup when tracer walks
		//    /proc and tries to synchronize all PIDs it sees.
		//    The PID should not exist anywhere, but we can still double check and
		//    make sure the PID is not tracked.
		// 2. It is a normal process executing, but we just sampled it when the kernel
		//    execve() is rebuilding the mappings and nothing is currently mapped.
		//    In this case we can handle it as process exit because everything about
		//    the process is changing: all mappings, comm, etc. If execve fails, we
		//    reaped it early. If execve succeeds, we will get new synchronization
		//    request soon, and handle it as a new process event.
		pm.processPIDExit(pid)
		return
	}

	util.AtomicUpdateMaxUint32(&pm.mappingStats.maxProcParseUsec, uint32(elapsed.Microseconds()))
	pm.mappingStats.totalProcParseUsec.Add(uint32(elapsed.Microseconds()))

	if pm.synchronizeMappings(pr, mappings) {
		log.Debugf("+ PID: %v", pid)
		// TODO: Fine-grained reported_pids handling (evaluate per-PID mapping
		// synchronization based on per-PID state such as time since last
		// synchronization). Currently we only remove a PID from reported_pids
		// if it's a new process and on process exit. This limits
		// the frequency of PID mapping synchronizations to PID lifetime in
		// reported_pids (which is dictated by REPORTED_PIDS_TIMEOUT in eBPF).

		// We're immediately removing a new PID from reported_pids, to cover
		// corner cases where processes load on startup in quick-succession
		// additional code (e.g. plugins, Asterisk).
		// Also see: Unified PID Events design doc
		pm.ebpf.RemoveReportedPID(pid)
	}
}

// CleanupPIDs executes a periodic synchronization of pidToProcessInfo table with system processes.
// NOTE: Exported only for tracer.
func (pm *ProcessManager) CleanupPIDs() {
	deadPids := make([]libpf.PID, 0, 16)

	pm.mu.RLock()
	for pid := range pm.pidToProcessInfo {
		if live, _ := proc.IsPIDLive(pid); !live {
			deadPids = append(deadPids, pid)
		}
	}
	pm.mu.RUnlock()

	for _, pid := range deadPids {
		pm.processPIDExit(pid)
	}

	if len(deadPids) > 0 {
		log.Debugf("Cleaned up %d dead PIDs", len(deadPids))
	}
}

// MetaForPID returns the process metadata for given PID.
func (pm *ProcessManager) MetaForPID(pid libpf.PID) ProcessMeta {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if procInfo, ok := pm.pidToProcessInfo[pid]; ok {
		return procInfo.meta
	}
	return ProcessMeta{}
}

// findMappingForTrace locates the mapping for a given host trace.
func (pm *ProcessManager) findMappingForTrace(pid libpf.PID, fid host.FileID,
	addr libpf.AddressOrLineno) (m Mapping, found bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	procInfo, ok := pm.pidToProcessInfo[pid]
	if !ok {
		return Mapping{}, false
	}

	fidMappings, ok := procInfo.mappingsByFileID[fid]
	if !ok {
		return Mapping{}, false
	}

	for _, candidate := range fidMappings {
		procSpaceVA := libpf.Address(uint64(addr) + candidate.Bias)
		mappingEnd := candidate.Vaddr + libpf.Address(candidate.Length)
		if procSpaceVA >= candidate.Vaddr && procSpaceVA <= mappingEnd {
			return *candidate, true
		}
	}

	return Mapping{}, false
}

func (pm *ProcessManager) ProcessedUntil(traceCaptureKTime times.KTime) {
	var err error
	defer func() {
		if err != nil {
			log.Error(err)
		}
	}()
	pm.mu.Lock()
	defer pm.mu.Unlock()

	nowKTime := times.GetKTime()
	log.Debugf("ProcessedUntil captureKT: %v latency: %v ms",
		traceCaptureKTime, (nowKTime-traceCaptureKTime)/1e6)

	for pid, pidExitKTime := range pm.exitEvents {
		if pidExitKTime > traceCaptureKTime {
			continue
		}

		delete(pm.pidToProcessInfo, pid)

		for _, instance := range pm.interpreters[pid] {
			if err2 := instance.Detach(pm.ebpf, pid); err2 != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to handle interpreted process exit for PID %d: %v",
						pid, err2))
			}
		}
		delete(pm.interpreters, pid)
		delete(pm.exitEvents, pid)
		log.Debugf("PID %v exit latency %v ms", pid, (nowKTime-pidExitKTime)/1e6)
	}
}

// Compile time check to make sure we satisfy the interface.
var _ tracehandler.TraceProcessor = (*ProcessManager)(nil)
