/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/peterbourgon/ff/v3"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/tracer"
)

const (
	// Default values for CLI flags
	defaultArgSamplesPerSecond       = 20
	defaultArgReporterInterval       = 5.0 * time.Second
	defaultArgMonitorInterval        = 5.0 * time.Second
	defaultArgPrivateMachineID       = ""
	defaultArgPrivateEnvironmentType = ""
	defaultProbabilisticThreshold    = tracer.ProbabilisticThresholdMax
	defaultProbabilisticInterval     = 1 * time.Minute
	defaultArgSendErrorFrames        = false

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultArgMapScaleFactor = 0
	// 1TB of executable address space
	maxArgMapScaleFactor = 8
)

// Help strings for command line arguments
var (
	noKernelVersionCheckHelp = "Disable checking kernel version for eBPF support. " +
		"Use at your own risk, to run the agent on older kernels with backported eBPF features."
	copyrightHelp      = "Show copyright and short license text."
	collAgentAddrHelp  = "The collection agent address in the format of host:port."
	verboseModeHelp    = "Enable verbose logging and debugging capabilities."
	tracersHelp        = "Comma-separated list of interpreter tracers to include."
	mapScaleFactorHelp = fmt.Sprintf("Scaling factor for eBPF map sizes. "+
		"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
		"Default is %d corresponding to 4GB of executable address space, max is %d.",
		defaultArgMapScaleFactor, maxArgMapScaleFactor)
	configFileHelp = "Path to the profiling agent configuration file."
	projectIDHelp  = "The project ID to split profiling data into logical groups. " +
		"Its value should be larger than 0 and smaller than 4096."
	cacheDirectoryHelp = "The directory where the profiling agent can store cached data."
	secretTokenHelp    = "The secret token associated with the project id."
	tagsHelp           = fmt.Sprintf("User-specified tags separated by ';'. "+
		"Each tag should match '%v'.", host.ValidTagRegex)
	disableTLSHelp          = "Disable encryption for data in transit."
	bpfVerifierLogLevelHelp = "Log level of the eBPF verifier output (0,1,2). Default is 0."
	bpfVerifierLogSizeHelp  = "Size in bytes that will be allocated for the eBPF " +
		"verifier output. Only takes effect if bpf-log-level > 0."
	versionHelp                = "Show version."
	probabilisticThresholdHelp = fmt.Sprintf("If set to a value between 1 and %d will enable "+
		"probabilistic profiling: "+
		"every probabilistic-interval a random number between 0 and %d is "+
		"chosen. If the given probabilistic-threshold is greater than this "+
		"random number, the agent will collect profiles from this system for "+
		"the duration of the interval.",
		tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1)
	probabilisticIntervalHelp = "Time interval for which probabilistic profiling will be " +
		"enabled or disabled."
)

// Variables for command line arguments
var (
	// Customer-visible flag variables.
	argNoKernelVersionCheck   bool
	argCollAgentAddr          string
	argCopyright              bool
	argVersion                bool
	argTracers                string
	argVerboseMode            bool
	argProjectID              uint
	argCacheDirectory         string
	argConfigFile             string
	argSecretToken            string
	argDisableTLS             bool
	argTags                   string
	argBpfVerifierLogLevel    uint
	argBpfVerifierLogSize     int
	argMapScaleFactor         uint
	argProbabilisticThreshold uint
	argProbabilisticInterval  time.Duration

	// "internal" flag variables.
	// Flag variables that are configured in "internal" builds will have to be assigned
	// a default value here, for their consumption in customer-facing builds.
	argEnvironmentType  = defaultArgPrivateEnvironmentType
	argMachineID        = defaultArgPrivateMachineID
	argMonitorInterval  = defaultArgMonitorInterval
	argReporterInterval = defaultArgReporterInterval
	argSamplesPerSecond = defaultArgSamplesPerSecond
	argSendErrorFrames  = defaultArgSendErrorFrames
)

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.
var fs = flag.NewFlagSet("otel-profiling-agent", flag.ExitOnError)

func parseArgs() error {
	// Please keep the parameters ordered alphabetically in the source-code.
	fs.UintVar(&argBpfVerifierLogLevel, "bpf-log-level", 0, bpfVerifierLogLevelHelp)
	fs.IntVar(&argBpfVerifierLogSize, "bpf-log-size", cebpf.DefaultVerifierLogSize,
		bpfVerifierLogSizeHelp)

	fs.StringVar(&argCacheDirectory, "cache-directory", "/var/cache/otel/profiling-agent",
		cacheDirectoryHelp)
	fs.StringVar(&argCollAgentAddr, "collection-agent", "",
		collAgentAddrHelp)
	fs.StringVar(&argConfigFile, "config", "/etc/otel/profiling-agent/agent.conf",
		configFileHelp)
	fs.BoolVar(&argCopyright, "copyright", false, copyrightHelp)

	fs.BoolVar(&argDisableTLS, "disable-tls", false, disableTLSHelp)

	fs.UintVar(&argMapScaleFactor, "map-scale-factor",
		defaultArgMapScaleFactor, mapScaleFactorHelp)

	fs.BoolVar(&argNoKernelVersionCheck, "no-kernel-version-check", false, noKernelVersionCheckHelp)

	fs.UintVar(&argProjectID, "project-id", 1, projectIDHelp)

	// Using a default value here to simplify OTEL review process.
	fs.StringVar(&argSecretToken, "secret-token", "abc123", secretTokenHelp)

	fs.StringVar(&argTags, "tags", "", tagsHelp)
	fs.StringVar(&argTracers, "t", "all", "Shorthand for -tracers.")
	fs.StringVar(&argTracers, "tracers", "all", tracersHelp)

	fs.BoolVar(&argVerboseMode, "v", false, "Shorthand for -verbose.")
	fs.BoolVar(&argVerboseMode, "verbose", false, verboseModeHelp)
	fs.BoolVar(&argVersion, "version", false, versionHelp)

	fs.UintVar(&argProbabilisticThreshold, "probabilistic-threshold",
		defaultProbabilisticThreshold, probabilisticThresholdHelp)
	fs.DurationVar(&argProbabilisticInterval, "probabilistic-interval",
		defaultProbabilisticInterval, probabilisticIntervalHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("OTEL_PROFILING_AGENT"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		// This will ignore configuration file (only) options that the current HA
		// does not recognize.
		ff.WithIgnoreUndefined(true),
		ff.WithAllowMissingConfigFile(true),
	)

	return err
}

func dumpArgs() {
	log.Debug("Config:")
	fs.VisitAll(func(f *flag.Flag) {
		log.Debug(fmt.Sprintf("%s: %v", f.Name, f.Value))
	})
}
