/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/host"
	hostmeta "github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/tracehandler"

	"github.com/elastic/otel-profiling-agent/hostmetadata"
	//	"github.com/elastic/otel-profiling-agent/metrics/reportermetrics"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/metrics/agentmetrics"
	"github.com/elastic/otel-profiling-agent/reporter"

	"github.com/elastic/otel-profiling-agent/tracer"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf/memorydebug"
	"github.com/elastic/otel-profiling-agent/libpf/vc"
)

// Short copyright / license text for eBPF code
var copyright = `Copyright (C) 2019-2024 Elasticsearch B.V.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). To request a copy of the
GPLv2 code, email us at profiling-feedback@elastic.co.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
`

type exitCode int

const (
	exitSuccess exitCode = 0
	exitFailure exitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	exitParseError exitCode = 2
)

func startTraceHandling(ctx context.Context, rep reporter.TraceReporter,
	times *config.Times, trc *tracer.Tracer) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	return tracehandler.Start(ctx, rep, trc, traceCh, times)
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failure to parse arguments: %s", err)
		return exitParseError
	}

	if argMapScaleFactor > 8 {
		fmt.Fprintf(os.Stderr, "eBPF map scaling factor %d exceeds limit (max: %d)\n",
			argMapScaleFactor, maxArgMapScaleFactor)
		return exitParseError
	}

	if argCopyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	if argVersion {
		fmt.Printf("%s\n", vc.Version())
		return exitSuccess
	}

	if argBpfVerifierLogLevel > 2 {
		fmt.Fprintf(os.Stderr, "invalid eBPF verifier log level: %d", argBpfVerifierLogLevel)
		return exitParseError
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	// Sanity check for probabilistic profiling arguments
	if argProbabilisticInterval < 1*time.Minute || argProbabilisticInterval > 5*time.Minute {
		fmt.Fprintf(os.Stderr, "Invalid argument for probabilistic-interval: use "+
			"a duration between 1 and 5 minutes")
		return exitParseError
	}
	if argProbabilisticThreshold < 1 ||
		argProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		fmt.Fprintf(os.Stderr, "Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
		return exitParseError
	}

	if argVerboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		dumpArgs()
	}

	startTime := time.Now()
	log.Infof("Starting OTEL profiling agent %s (revision %s, build timestamp %s)",
		vc.Version(), vc.Revision(), vc.BuildTimestamp())

	// Enable dumping of full heaps if the size of the allocated Golang heap
	// exceeds 150m, and start dumping memory profiles when the heap exceeds
	// 250m (only in debug builds, go build -tags debug).
	memorydebug.Init(1024*1024*250, 1024*1024*150)

	if !argNoKernelVersionCheck {
		var major, minor, patch uint32
		major, minor, patch, err = tracer.GetCurrentKernelVersion()
		if err != nil {
			msg := fmt.Sprintf("Failed to get kernel version: %v", err)
			log.Error(msg)
			return exitFailure
		}

		var minMajor, minMinor uint32
		switch runtime.GOARCH {
		case "amd64":
			minMajor, minMinor = 4, 15
		case "arm64":
			// Older ARM64 kernel versions have broken bpf_probe_read.
			// https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
			minMajor, minMinor = 5, 5
		default:
			msg := fmt.Sprintf("unsupported architecture: %s", runtime.GOARCH)
			log.Error(msg)
			return exitFailure
		}

		if major < minMajor || (major == minMajor && minor < minMinor) {
			msg := fmt.Sprintf("Host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
			log.Error(msg)
			return exitFailure
		}
	}

	if err = tracer.ProbeBPFSyscall(); err != nil {
		msg := fmt.Sprintf("Failed to probe eBPF syscall: %v", err)
		log.Error(msg)
		return exitFailure
	}

	if err = tracer.ProbeTracepoint(); err != nil {
		msg := fmt.Sprintf("Failed to probe tracepoint: %v", err)
		log.Error(msg)
		return exitFailure
	}

	validatedTags := hostmeta.ValidateTags(argTags)
	log.Debugf("Validated tags: %s", validatedTags)

	var presentCores uint16
	presentCores, err = hostmeta.PresentCPUCores()
	if err != nil {
		msg := fmt.Sprintf("Failed to read CPU file: %v", err)
		log.Error(msg)
		return exitFailure
	}

	// Retrieve host metadata that will be stored with the HA config, and
	// sent to the backend with certain RPCs.
	hostMetadataMap := make(map[string]string)
	if err = hostmeta.AddMetadata(argCollAgentAddr, hostMetadataMap); err != nil {
		msg := fmt.Sprintf("Unable to get host metadata for config: %v", err)
		log.Error(msg)
	}

	// Metadata retrieval may fail, in which case, we initialize all values
	// to the empty string.
	for _, hostMetadataKey := range []string{
		hostmeta.KeyIPAddress,
		hostmeta.KeyHostname,
		hostmeta.KeyKernelVersion,
	} {
		if _, ok := hostMetadataMap[hostMetadataKey]; !ok {
			hostMetadataMap[hostMetadataKey] = ""
		}
	}

	log.Debugf("Reading the configuration")
	conf := config.Config{
		ProjectID:              uint32(argProjectID),
		CacheDirectory:         argCacheDirectory,
		EnvironmentType:        argEnvironmentType,
		MachineID:              argMachineID,
		SecretToken:            argSecretToken,
		Tags:                   argTags,
		ValidatedTags:          validatedTags,
		Tracers:                argTracers,
		Verbose:                argVerboseMode,
		DisableTLS:             argDisableTLS,
		NoKernelVersionCheck:   argNoKernelVersionCheck,
		UploadSymbols:          false,
		BpfVerifierLogLevel:    argBpfVerifierLogLevel,
		BpfVerifierLogSize:     argBpfVerifierLogSize,
		MonitorInterval:        argMonitorInterval,
		ReportInterval:         argReporterInterval,
		SamplesPerSecond:       uint16(argSamplesPerSecond),
		CollectionAgentAddr:    argCollAgentAddr,
		ConfigurationFile:      argConfigFile,
		PresentCPUCores:        presentCores,
		TraceCacheIntervals:    6,
		MapScaleFactor:         uint8(argMapScaleFactor),
		StartTime:              startTime,
		IPAddress:              hostMetadataMap[hostmeta.KeyIPAddress],
		Hostname:               hostMetadataMap[hostmeta.KeyHostname],
		KernelVersion:          hostMetadataMap[hostmeta.KeyKernelVersion],
		ProbabilisticInterval:  argProbabilisticInterval,
		ProbabilisticThreshold: argProbabilisticThreshold,
	}
	if err = config.SetConfiguration(&conf); err != nil {
		msg := fmt.Sprintf("Failed to set configuration: %s", err)
		log.Error(msg)
		return exitFailure
	}
	log.Debugf("Done setting configuration")

	times := config.GetTimes()

	log.Debugf("Determining tracers to include")
	includeTracers, err := parseTracers(argTracers)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse the included tracers: %s", err)
		log.Error(msg)
		return exitFailure
	}

	if err = config.GenerateNewHostIDIfNecessary(); err != nil {
		msg := fmt.Sprintf("Failed to generate new host ID: %s", err)
		log.Error(msg)
		return exitFailure
	}

	log.Infof("Assigned ProjectID: %d HostID: %d", config.ProjectID(), config.HostID())

	// Scale the queues that report traces or information related to traces
	// with the number of CPUs, the reporting interval and the sample frequencies.
	tracesQSize := max(1024,
		uint32(runtime.NumCPU()*int(argReporterInterval.Seconds()*2)*argSamplesPerSecond))

	metadataCollector := hostmetadata.NewCollector(argCollAgentAddr)

	// TODO: Maybe abort execution if (some) metadata can not be collected
	hostMetadataMap = metadataCollector.GetHostMetadata()

	if bpfJITEnabled, found := hostMetadataMap["host:sysctl/net.core.bpf_jit_enable"]; found {
		if bpfJITEnabled == "0" {
			log.Warnf("The BPF JIT is disabled (net.core.bpf_jit_enable = 0). " +
				"Enable it to reduce CPU overhead.")
		}
	}

	// Network operations to CA start here
	var rep reporter.Reporter
	// Connect to the collection agent
	rep, err = reporter.StartOTLP(mainCtx, &reporter.Config{
		CollAgentAddr:           argCollAgentAddr,
		MaxRPCMsgSize:           33554432, // 32 MiB
		ExecMetadataMaxQueue:    1024,
		CountsForTracesMaxQueue: tracesQSize,
		MetricsMaxQueue:         1024,
		FramesForTracesMaxQueue: tracesQSize,
		FrameMetadataMaxQueue:   tracesQSize,
		HostMetadataMaxQueue:    2,
		FallbackSymbolsMaxQueue: 1024,
		DisableTLS:              argDisableTLS,
		MaxGRPCRetries:          5,
		Times:                   times,
	})
	if err != nil {
		msg := fmt.Sprintf("Failed to start reporting: %v", err)
		log.Error(msg)
		return exitFailure
	}

	metrics.SetReporter(rep)

	// Now that we've sent the first host metadata update, start a goroutine to keep sending updates
	// regularly. This is required so pf-web-service only needs to query metadata for bounded
	// periods of time.
	metadataCollector.StartMetadataCollection(mainCtx, rep)

	// Start agent specific metric retrieval and report them every second.
	agentMetricCancel, agentErr := agentmetrics.Start(mainCtx, 1*time.Second)
	if agentErr != nil {
		msg := fmt.Sprintf("Error starting the agent specific "+
			"metric collection: %s", agentErr)
		log.Error(msg)
		return exitFailure
	}
	defer agentMetricCancel()
	// Start reporter metric reporting with 60 second intervals.
	//	defer reportermetrics.Start(mainCtx, rep, 60*time.Second)()

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, rep, times, includeTracers, !argSendErrorFrames)
	if err != nil {
		msg := fmt.Sprintf("Failed to load eBPF tracer: %s", err)
		log.Error(msg)
		return exitFailure
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	// Initial scan of /proc filesystem to list currently-active PIDs and have them processed.
	if err := trc.StartPIDEventProcessor(mainCtx); err != nil {
		log.Errorf("Failed to list processes from /proc: %v", err)
	}
	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(argSamplesPerSecond); err != nil {
		msg := fmt.Sprintf("Failed to attach to perf event: %v", err)
		log.Error(msg)
		return exitFailure
	}
	log.Info("Attached tracer program")

	if argProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx,
			argProbabilisticInterval, argProbabilisticThreshold)
		log.Printf("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			msg := fmt.Sprintf("Failed to enable perf events: %v", err)
			log.Error(msg)
			return exitFailure
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		msg := fmt.Sprintf("Failed to attach scheduler monitor: %v", err)
		log.Error(msg)
		return exitFailure
	}

	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	log.Printf("Attached sched monitor")

	if err := startTraceHandling(mainCtx, rep, times, trc); err != nil {
		msg := fmt.Sprintf("Failed to start trace handling: %v", err)
		log.Error(msg)
		return exitFailure
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return exitSuccess
}
