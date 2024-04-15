/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/sysfs"

	log "github.com/sirupsen/logrus"
)

const (
	// Keys we get from procfs
	keyCPUVendorID          = "vendor"
	keyCPUModel             = "model"
	keyCPUModelName         = "model-name"
	keyCPUStepping          = "stepping"
	keyCPUFlags             = "flags"
	keyCPUBugs              = "bugs"
	keyCPUMaxMhz            = "clock/max-mhz"
	keyCPUMinMhz            = "clock/min-mhz"
	keyCPUScalingCurFreqMhz = "clock/scaling-cur-freq-mhz"
	keyCPUScalingDriver     = "clock/scaling-driver"
	keyCPUScalingGovernor   = "clock/scaling-governor"

	// Keys from CPUID
	keyCPUThreadsPerCore = "threads-per-core"
	keyCPUCoresPerSocket = "cores-per-socket"
	keyCPUNumCPUs        = "cpus"
	keyCPUCacheL1d       = "cache/L1d-kbytes"
	keyCPUCacheL1i       = "cache/L1i-kbytes"
	keyCPUCacheL2        = "cache/L2-kbytes"
	keyCPUCacheL3        = "cache/L3-kbytes"

	// Parsed from Kernel file
	keyCPUOnline = "online"

	keyPrefixCPU = "host:cpu"

	// measures
	kiloMemDiv = 1024
	megaHzDiv  = 1000
)

// We use CPUInfo from prometheus/procfs to fetch all data about all CPUs and group them as we want
// and get the caches (missing in procfs) from klauspost/cpuid, locking goroutines to CPUs

// A map of "host:cpu:<suffix>" keys to a map of socketIDs to values
type cpuInfo map[string]map[int]string

func key(suffix string) string {
	return fmt.Sprintf("%s/%s", keyPrefixCPU, suffix)
}

func (ci cpuInfo) add(socketID int, suffix, value string) {
	if value == "" {
		return
	}
	key := key(suffix)
	if _, ok := ci[key]; !ok {
		ci[key] = map[int]string{}
	}
	ci[key][socketID] = value
}

func (ci cpuInfo) addMany(socketID int, values map[string]string) {
	for suffix, value := range values {
		ci.add(socketID, suffix, value)
	}
}

// readCPUInfo will return a map with data about CPUs by reading from 3 sources:
// /proc/cpuinfo, /sys/device/system/cpu and the CPUID instruction.
func readCPUInfo() (cpuInfo, error) {
	info := cpuInfo{}
	sysDeviceCPUs, sysDeviceCPUFreqs, err := fetchCPUSysFs()
	if err != nil {
		return nil, err
	}

	cpuProcInfos, err := fetchCPUProcInfo()
	if err != nil {
		return nil, fmt.Errorf("error reading /proc/cpuinfo: %v", err)
	}

	// Online CPUs list will be used during the per-coreID iteration
	// to match the coreIDs that are online
	onlineCPUs, err := ParseCPUCoreIDs(CPUOnlinePath)
	if err != nil {
		return nil, fmt.Errorf("error reading online CPUs: %v", err)
	}

	// Iterate over all the logical cores and get their topology,
	// in order to group them per physical socket.
	// We expect all the 3 slices fetched via sysfs and procfs to have the same
	// number of entries, as they are fetched from the kernel, so we iterate
	// and fetch items from them using the slice index.
	for deviceID, cpu := range sysDeviceCPUs {
		// We need the topology to map logical cores onto physical sockets.
		topology, err := cpu.Topology()
		if err != nil {
			continue
		}

		socketID, err := strconv.Atoi(topology.PhysicalPackageID)
		// An error here should never happen but we want to log it in case it happens
		if err != nil {
			log.Errorf("Unable to convert socketID %s to integer: %v",
				topology.PhysicalPackageID, err)
			continue
		}

		// Checks if the deviceID is available in the online CPUs, using siblings
		siblings := topology.CoreSiblingsList
		info.add(socketID, keyCPUOnline, onlineCPUsFor(siblings, onlineCPUs))

		addCPU(info, &cpuProcInfos[deviceID], socketID)
		addCPUFrequencies(info, &sysDeviceCPUFreqs[deviceID], socketID)

		// CPUID data are stored in a map with key the logical coreID,
		// so we will use that instead of the index of the previous slices.
		coreID, err := strconv.Atoi(topology.CoreID)
		if err != nil {
			log.Errorf("Unable to convert coreID %s to integer: %v", topology.CoreID, err)
			continue
		}
		addCPUID(info, socketID, coreID)
	}

	return info, nil
}

func addCPUFrequencies(info cpuInfo, freqs *sysfs.SystemCPUCpufreqStats, socketID int) {
	// We want MegaHertz and the value is originally in KiloHertz
	if freqs.CpuinfoMaximumFrequency != nil {
		maxVal := *freqs.CpuinfoMaximumFrequency
		info.add(socketID, keyCPUMaxMhz, strconv.Itoa(int(maxVal)/megaHzDiv))
	}
	if freqs.CpuinfoMinimumFrequency != nil {
		minVal := *freqs.CpuinfoMinimumFrequency
		info.add(socketID, keyCPUMinMhz, strconv.Itoa(int(minVal)/megaHzDiv))
	}
	if freqs.ScalingCurrentFrequency != nil {
		scaling := *freqs.ScalingCurrentFrequency
		info.add(socketID, keyCPUScalingCurFreqMhz, strconv.Itoa(int(scaling)/megaHzDiv))
	}
	info.addMany(socketID, map[string]string{
		keyCPUScalingGovernor: freqs.Governor,
		keyCPUScalingDriver:   freqs.Driver,
	})
}

func addCPU(info cpuInfo, cpuProcInfos *procfs.CPUInfo, socketID int) {
	// We want a comma-separated, sorted list of flags and bugs, so we sort them here
	sort.Strings(cpuProcInfos.Flags)
	sort.Strings(cpuProcInfos.Bugs)
	info.addMany(socketID, map[string]string{
		keyCPUVendorID:  cpuProcInfos.VendorID,
		keyCPUModel:     cpuProcInfos.Model,
		keyCPUModelName: cpuProcInfos.ModelName,
		keyCPUStepping:  cpuProcInfos.Stepping,
		keyCPUFlags:     strings.Join(cpuProcInfos.Flags, ","),
		keyCPUBugs:      strings.Join(cpuProcInfos.Bugs, ","),
	})
}

func addCPUID(info cpuInfo, socketID, cpuID int) {
	cpuData, ok := _CPUIDs[cpuID]
	if ok {
		info.addMany(socketID, map[string]string{
			keyCPUThreadsPerCore: strconv.Itoa(cpuData.ThreadsPerCore),
			keyCPUCoresPerSocket: strconv.Itoa(cpuData.PhysicalCores),
			// We want KiloBytes and the value is originally in bytes
			keyCPUCacheL1i: strconv.Itoa(cpuData.Cache.L1I / kiloMemDiv),
			keyCPUCacheL1d: strconv.Itoa(cpuData.Cache.L1D / kiloMemDiv),
			keyCPUCacheL2:  strconv.Itoa(cpuData.Cache.L2 / kiloMemDiv),
			keyCPUCacheL3:  strconv.Itoa(cpuData.Cache.L3 / kiloMemDiv),
		})

		if cpuData.LogicalCores == 0 {
			// cpuData.LogicalCores returns the number of physical cores times the
			// number of threads that can run on each core. Architectures like KVM does
			// not have physical cores. Therefore we assume the number of threads per
			// core are on a single CPU.
			info.add(socketID, keyCPUNumCPUs, strconv.Itoa(cpuData.ThreadsPerCore))
		} else {
			info.add(socketID, keyCPUNumCPUs, strconv.Itoa(cpuData.LogicalCores))
		}
	} else {
		// If the map lookup changed, we populate the entries with an error string.
		errorString := "ERR"
		info.addMany(socketID, map[string]string{
			keyCPUThreadsPerCore: errorString,
			keyCPUCoresPerSocket: errorString,
			keyCPUNumCPUs:        errorString,
			keyCPUCacheL1i:       errorString,
			keyCPUCacheL1d:       errorString,
			keyCPUCacheL2:        errorString,
			keyCPUCacheL3:        errorString,
		})
	}
}

func fetchCPUProcInfo() ([]procfs.CPUInfo, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %v", err)
	}

	return fs.CPUInfo()
}

func fetchCPUSysFs() ([]sysfs.CPU, []sysfs.SystemCPUCpufreqStats, error) {
	sys, err := sysfs.NewDefaultFS()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read /sys filesystem: %v", err)
	}
	cpus, err := sys.CPUs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CPUS from /sys/device/system/cpu: %v", err)
	}
	freqs, err := sys.SystemCpufreq()
	if err != nil {
		return nil, nil,
			fmt.Errorf("failed to read frequencies from /sys/device/system/cpu: %v", err)
	}

	return cpus, freqs, nil
}

func onlineCPUsFor(siblingsList string, onlineCoreIDs []int) string {
	siblings, err := readCPURange(siblingsList)
	if err != nil {
		log.Errorf("Could not parse CPU siblings: %v", err)
	}
	sort.Ints(siblings)
	var onlines []int
	for _, c := range onlineCoreIDs {
		if x := sort.SearchInts(siblings, c); x < len(siblings) &&
			siblings[x] == c {
			onlines = append(onlines, c)
		}
	}
	return writeCPURange(onlines)
}

func writeCPURange(listOf []int) string {
	sort.Ints(listOf)
	var ret string
	for i := range listOf {
		if ret == "" {
			ret = strconv.Itoa(listOf[i])
			continue
		}
		if listOf[i] == listOf[i-1]+1 {
			ret = strings.TrimSuffix(ret, "-"+strconv.Itoa(listOf[i-1]))
			ret += "-" + strconv.Itoa(listOf[i])
		} else {
			ret += "," + strconv.Itoa(listOf[i])
		}
	}

	return ret
}
