/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package agent

import (
	"strconv"
	"time"
)

// TODO: Change to semconv / ECS
// Agent metadata keys
const (
	// Build metadata
	keyAgentVersion        = "profiling.agent.version"
	keyAgentRevision       = "profiling.agent.revision"
	keyAgentBuildTimestamp = "profiling.agent.build_timestamp"
	keyAgentStartTimeMilli = "profiling.agent.start_time"

	// Environment metadata
	// TODO: Remove this key
	keyAgentEnvHTTPSProxy = "profiling.agent.env_https_proxy"

	// Configuration metadata
	keyAgentConfigBpfLoglevel            = "profiling.agent.config.bpf_log_level"
	keyAgentConfigBpfLogSize             = "profiling.agent.config.bpf_log_size"
	keyAgentConfigCacheDirectory         = "profiling.agent.config.cache_directory"
	keyAgentConfigCollectionAgentAddr    = "profiling.agent.config.ca_address"
	keyAgentConfigurationFile            = "profiling.agent.config.file"
	keyAgentConfigTags                   = "profiling.agent.config.tags"
	keyAgentConfigDisableTLS             = "profiling.agent.config.disable_tls"
	keyAgentConfigNoKernelVersionCheck   = "profiling.agent.config.no_kernel_version_check"
	keyAgentConfigTracers                = "profiling.agent.config.tracers"
	keyAgentConfigKnownTracesEntries     = "profiling.agent.config.known_traces_entries"
	keyAgentConfigMapScaleFactor         = "profiling.agent.config.map_scale_factor"
	keyAgentConfigMaxElementsPerInterval = "profiling.agent.config.max_elements_per_interval"
	keyAgentConfigVerbose                = "profiling.agent.config.verbose"
	keyAgentConfigProbabilisticInterval  = "profiling.agent.config.probabilistic_interval"
	keyAgentConfigProbabilisticThreshold = "profiling.agent.config.probabilistic_threshold"
	keyAgentConfigPresentCPUCores        = "profiling.agent.config.present_cpu_cores"
)

// Config is the structure to pass agent-related host metadata.
type Config struct {
	Version                string
	Revision               string
	BuildTimestamp         string
	Tags                   string
	CollectionAgentAddr    string
	ConfigurationFile      string
	Tracers                string
	CacheDirectory         string
	EnvHTTPSProxy          string
	BpfVerifierLogSize     int
	BpfVerifierLogLevel    uint
	PresentCPUCores        uint16
	DisableTLS             bool
	NoKernelVersionCheck   bool
	Verbose                bool
	MapScaleFactor         uint
	StartTime              time.Time
	ProbabilisticInterval  time.Duration
	ProbabilisticThreshold uint
	TraceCacheEntries      uint32
	MaxElementsPerInterval uint32
}

var meta = make(map[string]string)

// SetAgentData sets the agent metadata.
// It is called once at startup of the agent, since the data is static.
func SetAgentData(c *Config) {
	meta[keyAgentVersion] = c.Version
	meta[keyAgentRevision] = c.Revision
	meta[keyAgentBuildTimestamp] = c.BuildTimestamp
	meta[keyAgentStartTimeMilli] = strconv.FormatInt(c.StartTime.UnixMilli(), 10)
	meta[keyAgentConfigBpfLoglevel] = strconv.FormatUint(uint64(c.BpfVerifierLogLevel), 10)
	meta[keyAgentConfigBpfLogSize] = strconv.Itoa(c.BpfVerifierLogSize)
	meta[keyAgentConfigCacheDirectory] = c.CacheDirectory
	meta[keyAgentConfigCollectionAgentAddr] = c.CollectionAgentAddr
	meta[keyAgentConfigurationFile] = c.ConfigurationFile
	meta[keyAgentConfigDisableTLS] = strconv.FormatBool(c.DisableTLS)
	meta[keyAgentConfigVerbose] = strconv.FormatBool(c.Verbose)
	meta[keyAgentConfigNoKernelVersionCheck] = strconv.FormatBool(c.NoKernelVersionCheck)
	meta[keyAgentConfigTags] = c.Tags
	meta[keyAgentConfigTracers] = c.Tracers
	meta[keyAgentConfigProbabilisticInterval] = c.ProbabilisticInterval.String()
	meta[keyAgentConfigProbabilisticThreshold] =
		strconv.FormatUint(uint64(c.ProbabilisticThreshold), 10)
	meta[keyAgentConfigPresentCPUCores] =
		strconv.FormatUint(uint64(c.PresentCPUCores), 10)
	meta[keyAgentConfigMapScaleFactor] = strconv.FormatUint(uint64(c.MapScaleFactor), 10)
	meta[keyAgentConfigKnownTracesEntries] =
		strconv.FormatUint(uint64(c.TraceCacheEntries), 10)
	meta[keyAgentConfigMaxElementsPerInterval] =
		strconv.FormatUint(uint64(c.MaxElementsPerInterval), 10)
	meta[keyAgentEnvHTTPSProxy] = c.EnvHTTPSProxy
}

func GetCollectionAgentAddr() string {
	return meta[keyAgentConfigCollectionAgentAddr]
}

// AddMetadata adds agent metadata to the result map.
func AddMetadata(result map[string]string) {
	for k, v := range meta {
		result[k] = v
	}
}
