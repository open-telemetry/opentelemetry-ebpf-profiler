/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package agent

import (
	"os"
	"strconv"

	"github.com/elastic/otel-profiling-agent/config"
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

// AddMetadata adds agent metadata to the result map.
func AddMetadata(result map[string]string) {
	result[keyAgentVersion] = config.Version()
	result[keyAgentRevision] = config.Revision()
	result[keyAgentBuildTimestamp] = config.BuildTimestamp()

	result[keyAgentStartTimeMilli] = strconv.FormatInt(config.StartTime().UnixMilli(), 10)

	bpfLogLevel, bpfLogSize := config.BpfVerifierLogSetting()
	result[keyAgentConfigBpfLoglevel] = strconv.FormatUint(uint64(bpfLogLevel), 10)
	result[keyAgentConfigBpfLogSize] = strconv.Itoa(bpfLogSize)

	result[keyAgentConfigCacheDirectory] = config.CacheDirectory()
	result[keyAgentConfigCollectionAgentAddr] = config.CollectionAgentAddr()
	result[keyAgentConfigurationFile] = config.ConfigurationFile()
	result[keyAgentConfigDisableTLS] = strconv.FormatBool(config.DisableTLS())
	result[keyAgentConfigNoKernelVersionCheck] = strconv.FormatBool(config.NoKernelVersionCheck())
	result[keyAgentConfigTags] = config.Tags()
	result[keyAgentConfigTracers] = config.Tracers()
	result[keyAgentConfigKnownTracesEntries] =
		strconv.FormatUint(uint64(config.TraceCacheEntries()), 10)
	result[keyAgentConfigMapScaleFactor] = strconv.FormatUint(uint64(config.MapScaleFactor()), 10)
	result[keyAgentConfigMaxElementsPerInterval] =
		strconv.FormatUint(uint64(config.MaxElementsPerInterval()), 10)
	result[keyAgentConfigVerbose] = strconv.FormatBool(config.Verbose())
	result[keyAgentConfigProbabilisticInterval] =
		config.GetTimes().ProbabilisticInterval().String()
	result[keyAgentConfigProbabilisticThreshold] =
		strconv.FormatUint(uint64(config.ProbabilisticThreshold()), 10)
	result[keyAgentConfigPresentCPUCores] =
		strconv.FormatUint(uint64(config.PresentCPUCores()), 10)
	result[keyAgentEnvHTTPSProxy] = os.Getenv("HTTPS_PROXY")
}
