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
	keyAgentVersion        = "agent:version"
	keyAgentRevision       = "agent:revision"
	keyAgentBuildTimestamp = "agent:build_timestamp"
	keyAgentStartTimeMilli = "agent:start_time_milli"

	// Environment metadata
	keyAgentEnvHTTPSProxy = "agent:env_https_proxy"

	// Configuration metadata
	keyAgentConfigBpfLoglevel            = "agent:config_bpf_log_level"
	keyAgentConfigBpfLogSize             = "agent:config_bpf_log_size"
	keyAgentConfigCacheDirectory         = "agent:config_cache_directory"
	keyAgentConfigCollectionAgentAddr    = "agent:config_ca_address"
	keyAgentConfigurationFile            = "agent:config_file"
	keyAgentConfigTags                   = "agent:config_tags"
	keyAgentConfigDisableTLS             = "agent:config_disable_tls"
	keyAgentConfigNoKernelVersionCheck   = "agent:config_no_kernel_version_check"
	keyAgentConfigTracers                = "agent:config_tracers"
	keyAgentConfigKnownTracesEntries     = "agent:config_known_traces_entries"
	keyAgentConfigMapScaleFactor         = "agent:config_map_scale_factor"
	keyAgentConfigMaxElementsPerInterval = "agent:config_max_elements_per_interval"
	keyAgentConfigVerbose                = "agent:config_verbose"
	keyAgentConfigProbabilisticInterval  = "agent:config_probabilistic_interval"
	keyAgentConfigProbabilisticThreshold = "agent:config_probabilistic_threshold"
	// nolint:gosec
	keyAgentConfigPresentCPUCores = "agent:config_present_cpu_cores"
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
