/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
)

const (
	traceCacheMinSize = 65536
)

// Config is the structure to pass the configuration into host-agent.
type Config struct {
	EnvironmentType        string
	MachineID              string
	SecretToken            string
	Tags                   string
	ValidatedTags          string
	CollectionAgentAddr    string
	ConfigurationFile      string
	Tracers                string
	CacheDirectory         string
	BpfVerifierLogSize     int
	BpfVerifierLogLevel    uint
	MonitorInterval        time.Duration
	TracePollInterval      time.Duration
	ReportInterval         time.Duration
	ProjectID              uint32
	SamplesPerSecond       uint16
	PresentCPUCores        uint16
	DisableTLS             bool
	UploadSymbols          bool
	NoKernelVersionCheck   bool
	TraceCacheIntervals    uint8
	Verbose                bool
	MapScaleFactor         uint8
	StartTime              time.Time
	ProbabilisticInterval  time.Duration
	ProbabilisticThreshold uint

	// Bits of hostmetadata that we save in config so that they can be
	// conveniently accessed globally in the agent.
	IPAddress     string
	Hostname      string
	KernelVersion string
}

// Profiling specific variables which are set once at startup of the agent.
// To avoid passing them as argument to every function, they are declared
// on package scope.
var (
	// hostID represents project wide unique id to identify the host.
	hostID uint64
	// projectID is read from the provided configuration file and sent to the collection agent
	// along with traces to identify the project that they belong to.
	projectID uint32
	// secretToken is read from the provided configuration file and sent to the collection agent
	// along with traces to authenticate the data being sent for a project
	secretToken string
	// tags contains user-specified tags as passed-in by the user
	tags string
	// validatedTags contains user-specified tags that have passed validation
	validatedTags string
	// collectionAgentAddr contains the collection agent address in host:port format
	collectionAgentAddr string
	// configurationFile contains the path to the profiling agent's configuration file
	configurationFile string
	// tracers contains the user-specified tracers to enable
	tracers string

	// verbose indicates if host agent was started with the verbose argument
	verbose bool
	// disableTLS indicates if TLS to collection agent is disabled
	disableTLS bool
	// noKernelVersionCheck indicates if kernel version checking for eBPF support is disabled
	noKernelVersionCheck bool
	// uploadSymbols indicates whether automatic uploading of symbols is enabled
	uploadSymbols bool
	// bpfVerifierLogLevel holds the defined log level of the eBPF verifier.
	// Currently there are three different log levels applied by the kernel verifier:
	// 0 - no logging
	// BPF_LOG_LEVEL1 (1) - enable logging
	// BPF_LOG_LEVEL2 (2) - more logging
	//
	// Some older kernels do not handle BPF_LOG_LEVEL2.
	bpfVerifierLogLevel uint32
	// bpfVerifierLogSize defines the number of bytes that are pre-allocated to hold the output
	// of the eBPF verifier log.
	bpfVerifierLogSize int
	// maxElementsPerInterval defines the maximum number of possible elements reported per
	// monitor interval (MonitorInterval).
	maxElementsPerInterval uint32

	// traceCacheIntervals defines the number of monitor intervals that should fit into the
	// tracehandler LRUs. Effectively, this is a sizing factor for those caches.
	traceCacheIntervals uint8

	// samplesPerSecond holds the configured numbers of samples per second.
	samplesPerSecond uint16

	// startTime holds the HA start time
	startTime time.Time

	// mapScaleFactor holds a scaling factor for sizing eBPF maps
	mapScaleFactor uint8

	// ipAddress holds the IP address of the interface through which the agent traffic is routed
	ipAddress string

	// hostname hosts the hostname of the machine that is running the agent
	hostname string

	// kernelVersion holds the kernel release (uname -r) of the machine that is running the agent
	kernelVersion string

	// probabilisticThreshold sets the threshold for probabilistic profiling
	probabilisticThreshold uint

	// presentCPUCores holds the number of CPU cores
	presentCPUCores uint16
)

// cacheDirectory is the top level directory that should be used for cache files. These are files
// that can be deleted without loss of data.
var cacheDirectory = "/var/cache/otel/profiling-agent"

// configurationSet signals that SetConfiguration() has been successfully called and
// the variables it sets can be read.
var configurationSet = false

func SetConfiguration(conf *Config) error {
	var err error

	projectID = conf.ProjectID

	if projectID == 0 || projectID > 4095 {
		return fmt.Errorf("invalid project id %d (need > 0 and < 4096)", projectID)
	}

	if conf.SecretToken == "" {
		return fmt.Errorf("missing SecretToken")
	}
	secretToken = conf.SecretToken

	tags = conf.Tags
	validatedTags = conf.ValidatedTags
	verbose = conf.Verbose
	samplesPerSecond = conf.SamplesPerSecond
	probabilisticThreshold = conf.ProbabilisticThreshold
	presentCPUCores = conf.PresentCPUCores

	bpfVerifierLogLevel = uint32(conf.BpfVerifierLogLevel)
	bpfVerifierLogSize = conf.BpfVerifierLogSize

	// The environment type (aws/gcp/bare metal) is overridden vs. the default auto-detect.
	// WARN: Environment type and machineID are internal flag arguments and not exposed
	// in customer-facing builds.
	if conf.EnvironmentType != "" {
		var environment EnvironmentType
		if environment, err = environmentTypeFromString(conf.EnvironmentType); err != nil {
			return fmt.Errorf("invalid environment '%s': %s", conf.EnvironmentType, err)
		}

		// If the environment is overridden, the machine ID also needs to be overridden.
		machineID, err := strconv.ParseUint(conf.MachineID, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid machine ID '%s': %s", conf.MachineID, err)
		}
		if machineID == 0 {
			return fmt.Errorf(
				"the machine ID must be specified with the environment (and non-zero)")
		}
		log.Debugf("User provided environment (%s) and machine ID (0x%x)", environment,
			machineID)
		setEnvironment(environment)
		hostID = machineID
	} else if conf.MachineID != "" {
		return fmt.Errorf("you can only specify the machine ID if you also provide the environment")
	}

	cacheDirectory = conf.CacheDirectory
	if _, err := os.Stat(cacheDirectory); os.IsNotExist(err) {
		log.Debugf("Creating cache directory '%s'", cacheDirectory)
		if err := os.MkdirAll(cacheDirectory, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create cache directory (%s): %s", cacheDirectory, err)
		}
	}

	collectionAgentAddr = conf.CollectionAgentAddr
	configurationFile = conf.ConfigurationFile
	disableTLS = conf.DisableTLS
	noKernelVersionCheck = conf.NoKernelVersionCheck
	uploadSymbols = conf.UploadSymbols
	tracers = conf.Tracers
	startTime = conf.StartTime
	mapScaleFactor = conf.MapScaleFactor

	// Set time values that do not have defaults in times.go
	times.reportInterval = conf.ReportInterval
	times.monitorInterval = conf.MonitorInterval
	times.probabilisticInterval = conf.ProbabilisticInterval

	maxElementsPerInterval = uint32(conf.SamplesPerSecond *
		uint16(conf.MonitorInterval.Seconds()) * conf.PresentCPUCores)
	traceCacheIntervals = conf.TraceCacheIntervals

	ipAddress = conf.IPAddress
	hostname = conf.Hostname
	kernelVersion = conf.KernelVersion

	configurationSet = true
	return nil
}

// SamplesPerSecond returns the configured samples per second.
func SamplesPerSecond() uint16 {
	return samplesPerSecond
}

// MaxElementsPerInterval returns the maximum of possible elements reported per interval based on
// the number of cores, samples per second and monitor interval.
func MaxElementsPerInterval() uint32 {
	return maxElementsPerInterval
}

// TraceCacheEntries defines the maximum number of elements for the caches in tracehandler.
//
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit:cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g. too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here. Also see:
// https://github.com/elastic/otel-profiling-agent/pull/2120#issuecomment-1043024813
func TraceCacheEntries() uint32 {
	size := maxElementsPerInterval * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return libpf.NextPowerOfTwo(size)
}

// Verbose indicates if the agent is running with verbose enabled.
func Verbose() bool {
	return verbose
}

// BpfVerifierLogSetting returns the eBPF verifier log settings.
func BpfVerifierLogSetting() (level uint32, size int) {
	return bpfVerifierLogLevel, bpfVerifierLogSize
}

// HostID returns the hostID of the running agent. The host ID is calculated by calling
// GenerateNewHostIDIfNecessary().
func HostID() uint64 {
	if hostID == 0 {
		log.Fatalf("HostID is not set")
	}
	return hostID
}

// ProjectID returns the projectID
func ProjectID() uint32 {
	if !configurationSet {
		log.Fatal("Cannot access ProjectID. Configuration has not been read")
	}
	return projectID
}

// SecretToken returns the secretToken associated with the project
func SecretToken() string {
	if !configurationSet {
		log.Fatal("Cannot access SecretToken. Configuration has not been read")
	}
	return secretToken
}

// CacheDirectory returns the cacheDirectory.
func CacheDirectory() string {
	return cacheDirectory
}

// User-specified tags as passed-in by the user
func Tags() string {
	return tags
}

// User-specified tags that have passed validation
func ValidatedTags() string {
	return validatedTags
}

// Collection agent address in host:port format
func CollectionAgentAddr() string {
	return collectionAgentAddr
}

// Path to profiling agent's configuration file
func ConfigurationFile() string {
	return configurationFile
}

// Indicates if TLS to collection agent is disabled
func DisableTLS() bool {
	return disableTLS
}

// Indicates if kernel version checking for eBPF support is disabled
func NoKernelVersionCheck() bool {
	return noKernelVersionCheck
}

// Indicates whether automatic uploading of symbols is enabled
func UploadSymbols() bool {
	return uploadSymbols
}

// User-specified tracers to enable
func Tracers() string {
	return tracers
}

// HA start time
func StartTime() time.Time {
	return startTime
}

// Scaling factor for eBPF maps
func MapScaleFactor() uint8 {
	return mapScaleFactor
}

// IP address of the interface through which the agent traffic is routed
func IPAddress() string {
	return ipAddress
}

// Hostname of the machine that is running the agent
func Hostname() string {
	return hostname
}

// Kernel release (uname -r) of the machine that is running the agent
func KernelVersion() string {
	return kernelVersion
}

// Threshold for probabilistic profiling
func ProbabilisticThreshold() uint {
	return probabilisticThreshold
}

// Number of CPU cores
func PresentCPUCores() uint16 {
	return presentCPUCores
}
