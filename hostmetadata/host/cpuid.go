//go:build linux
// +build linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/cpuid/v2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

const CPUOnlinePath = "/sys/devices/system/cpu/online"
const CPUPresentPath = "/sys/devices/system/cpu/present"

// This variable holds the CPUInfo: as key the core ID, as value the CPUID fetched from it.
// We duplicate the data at startup to be able to split and aggregate
// with more dimensions later.
var _CPUIDs map[int]*cpuid.CPUInfo

// CPUID is an expensive instruction so we want to call it only once
// when we load the host-agent.
// We rely on online CPUs as count of logical cores where we will run CPUID.
// If reading online CPUs fails, we will leave the list of CPUInfo empty,
// and no CPU metadata will be collected.
func init() {
	coreIDs, err := ParseCPUCoreIDs(CPUOnlinePath)
	if err != nil {
		// We could panic here, but we prefer not to fail and have missing metadata.
		log.Errorf("Could not get number of CPUs: %v", err)
		return
	}
	_CPUIDs, err = runCPUIDOnAllCores(coreIDs)
	if err != nil {
		log.Warnf("Metadata might be incomplete, could not execute CPUID on all cores: %v", err)
		return
	}
}

// PresentCPUCores returns the number of present CPU cores.
func PresentCPUCores() (uint16, error) {
	coreIDs, err := ParseCPUCoreIDs(CPUPresentPath)
	if err != nil {
		return 0, fmt.Errorf("reading '%s' failed: %v", CPUPresentPath, err)
	}
	return uint16(len(coreIDs)), nil
}

// This function should only be called in the init() of this package!
// It is expensive to call CPUID so we store its result into a package-scoped variable.
// This function ensures that we run CPUID on all available sockets.
func runCPUIDOnAllCores(numCPUs []int) (map[int]*cpuid.CPUInfo, error) {
	ret := make(map[int]*cpuid.CPUInfo, len(numCPUs))

	// A Mutex is required to protect the concurrent access to the CPU singleton.
	mx := sync.Mutex{}
	// We use an errgroup to spawn independent goroutines, one for each core.
	g := errgroup.Group{}
	for _, id := range numCPUs {
		cpuID := id
		// Each goroutine will be locked to a thread, and the thread will be scheduled
		// via affinity on the logical core using its ID.
		g.Go(func() error {
			runtime.LockOSThread()
			mask := &unix.CPUSet{}
			mask.Zero()
			mask.Set(cpuID)
			if err := unix.SchedSetaffinity(0, mask); err != nil {
				return fmt.Errorf("could not set CPU affinity on core %d: %v", cpuID, err)
			}
			mx.Lock()
			cpuid.Detect()
			ret[cpuID] = &cpuid.CPU
			mx.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return ret, err
	}

	return ret, nil
}

// Read CPUs from /sys/device and report the core IDs as a list of integers.
func ParseCPUCoreIDs(cpuPath string) ([]int, error) {
	buf, err := os.ReadFile(cpuPath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %v", cpuPath, err)
	}
	return readCPURange(string(buf))
}

// Since the format of online CPUs can contain comma-separated, ranges or a single value
// we need to try and parse it in all its different forms.
// Reference: https://www.kernel.org/doc/Documentation/admin-guide/cputopology.rst
func readCPURange(cpuRangeStr string) ([]int, error) {
	var cpus []int
	cpuRangeStr = strings.Trim(cpuRangeStr, "\n ")
	for _, cpuRange := range strings.Split(cpuRangeStr, ",") {
		rangeOp := strings.SplitN(cpuRange, "-", 2)
		first, err := strconv.ParseUint(rangeOp[0], 10, 32)
		if err != nil {
			return nil, err
		}
		if len(rangeOp) == 1 {
			cpus = append(cpus, int(first))
			continue
		}
		last, err := strconv.ParseUint(rangeOp[1], 10, 32)
		if err != nil {
			return nil, err
		}
		for n := first; n <= last; n++ {
			cpus = append(cpus, int(n))
		}
	}
	return cpus, nil
}
