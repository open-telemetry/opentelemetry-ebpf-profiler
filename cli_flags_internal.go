/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This file contains the CLI flags that are not going to be released to our customers.
// Only builds tagged with 'internal' will contain the additional arguments.
//go:build internal

package main

var (
	// Flag variables, pprof-specific
	argEnablePProf    bool
	argSaveCPUProfile bool

	// Help messages
	samplesPerSecondHelp = "Set the frequency (in Hz) of stack trace sampling."
	reporterIntervalHelp = "Set the reporter's interval in seconds."
	monitorIntervalHelp  = "Set the monitor interval in seconds."
	environmentTypeHelp  = "The type of environment."
	machineIDHelp        = "The machine ID."
	exitDelayHelp        = "Delay before exiting."
	enablePProfHelp      = "Enables PProf profiling"
	saveCPUProfileHelp   = "Save CPU pprof profile to `cpu.pprof`"
	sendErrorFramesHelp  = "Send error frames (devfiler only, breaks Kibana)"
)

func init() {
	fs.BoolVar(&argEnablePProf, "enable-pprof", false,
		enablePProfHelp)

	fs.BoolVar(&argSaveCPUProfile, "save-cpuprofile", false,
		saveCPUProfileHelp)

	// It would be nice if we could somehow have a private and a public flagset (and move these
	// elements to the private set; sadly flagset.Parse() returns error on unexpected flags, and
	// there is no good way to extract the 'already parsed' flags. This leads to a situation where
	// we can't parse the command line into two flagsets easily, because we'd somehow need to know
	// which arguments belong in the one flagset and which ones belong in the other.
	// We put the private flags into 'internal' builds, which we will not distribute to customers.
	fs.StringVar(&argEnvironmentType, "private-environment-type", defaultArgPrivateEnvironmentType,
		environmentTypeHelp)
	fs.StringVar(&argMachineID, "private-machine-id", defaultArgPrivateMachineID,
		machineIDHelp)
	fs.IntVar(&argSamplesPerSecond, "private-samples-per-second", defaultArgSamplesPerSecond,
		samplesPerSecondHelp)
	fs.DurationVar(&argReporterInterval, "private-reporter-interval", defaultArgReporterInterval,
		reporterIntervalHelp)
	fs.DurationVar(&argMonitorInterval, "private-monitor-interval", defaultArgMonitorInterval,
		monitorIntervalHelp)
	fs.BoolVar(&argSendErrorFrames, "private-send-error-frames", defaultArgSendErrorFrames,
		sendErrorFramesHelp)
}
