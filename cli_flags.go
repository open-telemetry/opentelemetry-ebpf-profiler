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

	"github.com/peterbourgon/ff/v3"
	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer"
)

const (
	// Default values for CLI flags
	defaultArgSamplesPerSecond    = 20
	defaultArgReporterInterval    = 5.0 * time.Second
	defaultArgMonitorInterval     = 5.0 * time.Second
	defaultClockSyncInterval      = 3 * time.Minute
	defaultProbabilisticThreshold = tracer.ProbabilisticThresholdMax
	defaultProbabilisticInterval  = 1 * time.Minute
	defaultArgSendErrorFrames     = false

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
	disableTLSHelp             = "Disable encryption for data in transit."
	bpfVerifierLogLevelHelp    = "Log level of the eBPF verifier output (0,1,2). Default is 0."
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
	pprofHelp             = "Listening address (e.g. localhost:6060) to serve pprof information."
	samplesPerSecondHelp  = "Set the frequency (in Hz) of stack trace sampling."
	reporterIntervalHelp  = "Set the reporter's interval in seconds."
	monitorIntervalHelp   = "Set the monitor interval in seconds."
	clockSyncIntervalHelp = "Set the sync interval with the realtime clock. " +
		"If zero, monotonic-realtime clock sync will be performed once, " +
		"on agent startup, but not periodically."
	sendErrorFramesHelp = "Send error frames (devfiler only, breaks Kibana)"
)

type arguments struct {
	bpfVerifierLogLevel    uint
	collAgentAddr          string
	copyright              bool
	disableTLS             bool
	mapScaleFactor         uint
	monitorInterval        time.Duration
	clockSyncInterval      time.Duration
	noKernelVersionCheck   bool
	pprofAddr              string
	probabilisticInterval  time.Duration
	probabilisticThreshold uint
	reporterInterval       time.Duration
	samplesPerSecond       int
	sendErrorFrames        bool
	tracers                string
	verboseMode            bool
	version                bool

	fs *flag.FlagSet
}

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.

func parseArgs() (*arguments, error) {
	var args arguments

	fs := flag.NewFlagSet("otel-profiling-agent", flag.ExitOnError)

	// Please keep the parameters ordered alphabetically in the source-code.
	fs.UintVar(&args.bpfVerifierLogLevel, "bpf-log-level", 0, bpfVerifierLogLevelHelp)

	fs.StringVar(&args.collAgentAddr, "collection-agent", "", collAgentAddrHelp)
	fs.BoolVar(&args.copyright, "copyright", false, copyrightHelp)

	fs.BoolVar(&args.disableTLS, "disable-tls", false, disableTLSHelp)

	fs.UintVar(&args.mapScaleFactor, "map-scale-factor",
		defaultArgMapScaleFactor, mapScaleFactorHelp)

	fs.DurationVar(&args.monitorInterval, "monitor-interval", defaultArgMonitorInterval,
		monitorIntervalHelp)

	fs.DurationVar(&args.clockSyncInterval, "clock-sync-interval", defaultClockSyncInterval,
		clockSyncIntervalHelp)

	fs.BoolVar(&args.noKernelVersionCheck, "no-kernel-version-check", false,
		noKernelVersionCheckHelp)

	fs.StringVar(&args.pprofAddr, "pprof", "", pprofHelp)

	fs.DurationVar(&args.probabilisticInterval, "probabilistic-interval",
		defaultProbabilisticInterval, probabilisticIntervalHelp)
	fs.UintVar(&args.probabilisticThreshold, "probabilistic-threshold",
		defaultProbabilisticThreshold, probabilisticThresholdHelp)

	fs.DurationVar(&args.reporterInterval, "reporter-interval", defaultArgReporterInterval,
		reporterIntervalHelp)

	fs.IntVar(&args.samplesPerSecond, "samples-per-second", defaultArgSamplesPerSecond,
		samplesPerSecondHelp)

	fs.BoolVar(&args.sendErrorFrames, "send-error-frames", defaultArgSendErrorFrames,
		sendErrorFramesHelp)

	fs.StringVar(&args.tracers, "t", "all", "Shorthand for -tracers.")
	fs.StringVar(&args.tracers, "tracers", "all", tracersHelp)

	fs.BoolVar(&args.verboseMode, "v", false, "Shorthand for -verbose.")
	fs.BoolVar(&args.verboseMode, "verbose", false, verboseModeHelp)
	fs.BoolVar(&args.version, "version", false, versionHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	args.fs = fs

	return &args, ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("OTEL_PROFILING_AGENT"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		// This will ignore configuration file (only) options that the current HA
		// does not recognize.
		ff.WithIgnoreUndefined(true),
		ff.WithAllowMissingConfigFile(true),
	)
}

func (args *arguments) dump() {
	log.Debug("Config:")
	args.fs.VisitAll(func(f *flag.Flag) {
		log.Debug(fmt.Sprintf("%s: %v", f.Name, f.Value))
	})
}
