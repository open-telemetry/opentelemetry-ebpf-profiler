// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/peterbourgon/ff/v3"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/tracer"
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
	defaultOffCPUThreshold        = tracer.OffCPUThresholdMax

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultArgMapScaleFactor = 0
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
		defaultArgMapScaleFactor, controller.MaxArgMapScaleFactor)
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
	offCPUThresholdHelp = fmt.Sprintf("If set to a value between 1 and %d will enable "+
		"off cpu profiling: Every time an off-cpu entry point is hit, a random number between "+
		"0 and %d is chosen. If the given threshold is greater than this random number, the off "+
		"cpu trace is collected and reported.",
		tracer.OffCPUThresholdMax-1, tracer.OffCPUThresholdMax-1)
)

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.

func parseArgs() (*controller.Config, error) {
	var args controller.Config

	fs := flag.NewFlagSet("ebpf-profiler", flag.ExitOnError)

	// Please keep the parameters ordered alphabetically in the source-code.
	fs.UintVar(&args.BpfVerifierLogLevel, "bpf-log-level", 0, bpfVerifierLogLevelHelp)

	fs.StringVar(&args.CollAgentAddr, "collection-agent", "", collAgentAddrHelp)
	fs.BoolVar(&args.Copyright, "copyright", false, copyrightHelp)

	fs.BoolVar(&args.DisableTLS, "disable-tls", false, disableTLSHelp)

	fs.UintVar(&args.MapScaleFactor, "map-scale-factor",
		defaultArgMapScaleFactor, mapScaleFactorHelp)

	fs.DurationVar(&args.MonitorInterval, "monitor-interval", defaultArgMonitorInterval,
		monitorIntervalHelp)

	fs.DurationVar(&args.ClockSyncInterval, "clock-sync-interval", defaultClockSyncInterval,
		clockSyncIntervalHelp)

	fs.BoolVar(&args.NoKernelVersionCheck, "no-kernel-version-check", false,
		noKernelVersionCheckHelp)

	fs.StringVar(&args.PprofAddr, "pprof", "", pprofHelp)

	fs.DurationVar(&args.ProbabilisticInterval, "probabilistic-interval",
		defaultProbabilisticInterval, probabilisticIntervalHelp)
	fs.UintVar(&args.ProbabilisticThreshold, "probabilistic-threshold",
		defaultProbabilisticThreshold, probabilisticThresholdHelp)

	fs.DurationVar(&args.ReporterInterval, "reporter-interval", defaultArgReporterInterval,
		reporterIntervalHelp)

	fs.IntVar(&args.SamplesPerSecond, "samples-per-second", defaultArgSamplesPerSecond,
		samplesPerSecondHelp)

	fs.BoolVar(&args.SendErrorFrames, "send-error-frames", defaultArgSendErrorFrames,
		sendErrorFramesHelp)

	fs.StringVar(&args.Tracers, "t", "all", "Shorthand for -tracers.")
	fs.StringVar(&args.Tracers, "tracers", "all", tracersHelp)

	fs.BoolVar(&args.VerboseMode, "v", false, "Shorthand for -verbose.")
	fs.BoolVar(&args.VerboseMode, "verbose", false, verboseModeHelp)
	fs.BoolVar(&args.Version, "version", false, versionHelp)

	fs.UintVar(&args.OffCPUThreshold, "off-cpu-threshold",
		defaultOffCPUThreshold, offCPUThresholdHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	args.Fs = fs

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
