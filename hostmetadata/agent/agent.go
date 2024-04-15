/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package agent

import (
	"fmt"
	"os"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf/vc"
)

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
	keyAgentConfigUploadSymbols          = "agent:config_upload_symbols"
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
	result[keyAgentVersion] = vc.Version()
	result[keyAgentRevision] = vc.Revision()

	result[keyAgentBuildTimestamp] = vc.BuildTimestamp()
	result[keyAgentStartTimeMilli] = fmt.Sprintf("%d", config.StartTime().UnixMilli())

	bpfLogLevel, bpfLogSize := config.BpfVerifierLogSetting()
	result[keyAgentConfigBpfLoglevel] = fmt.Sprintf("%d", bpfLogLevel)
	result[keyAgentConfigBpfLogSize] = fmt.Sprintf("%d", bpfLogSize)

	result[keyAgentConfigCacheDirectory] = config.CacheDirectory()
	result[keyAgentConfigCollectionAgentAddr] = config.CollectionAgentAddr()
	result[keyAgentConfigurationFile] = config.ConfigurationFile()
	result[keyAgentConfigDisableTLS] = fmt.Sprintf("%v", config.DisableTLS())
	result[keyAgentConfigNoKernelVersionCheck] = fmt.Sprintf("%v", config.NoKernelVersionCheck())
	result[keyAgentConfigUploadSymbols] = fmt.Sprintf("%v", config.UploadSymbols())
	result[keyAgentConfigTags] = config.Tags()
	result[keyAgentConfigTracers] = config.Tracers()
	result[keyAgentConfigKnownTracesEntries] = fmt.Sprintf("%d", config.TraceCacheEntries())
	result[keyAgentConfigMapScaleFactor] = fmt.Sprintf("%d", config.MapScaleFactor())
	result[keyAgentConfigMaxElementsPerInterval] =
		fmt.Sprintf("%d", config.MaxElementsPerInterval())
	result[keyAgentConfigVerbose] = fmt.Sprintf("%v", config.Verbose())
	result[keyAgentConfigProbabilisticInterval] =
		config.GetTimes().ProbabilisticInterval().String()
	result[keyAgentConfigProbabilisticThreshold] =
		fmt.Sprintf("%d", config.ProbabilisticThreshold())
	result[keyAgentConfigPresentCPUCores] =
		fmt.Sprintf("%d", config.PresentCPUCores())
	result[keyAgentEnvHTTPSProxy] = os.Getenv("HTTPS_PROXY")
}
