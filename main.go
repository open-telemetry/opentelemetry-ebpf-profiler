/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	//nolint:gosec
	_ "net/http/pprof"

	"github.com/elastic/otel-profiling-agent/containermetadata"
	"github.com/elastic/otel-profiling-agent/env"
	"github.com/elastic/otel-profiling-agent/vc"
	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/host"
	hostmeta "github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/tracehandler"

	"github.com/elastic/otel-profiling-agent/hostmetadata"
	"github.com/elastic/otel-profiling-agent/metrics/reportermetrics"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/metrics/agentmetrics"
	"github.com/elastic/otel-profiling-agent/reporter"

	"github.com/elastic/otel-profiling-agent/tracer"

	log "github.com/sirupsen/logrus"
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

	containerMetadataHandler, err := containermetadata.GetHandler(ctx, times.MonitorInterval())
	if err != nil {
		return fmt.Errorf("failed to create container metadata handler: %v", err)
	}

	_, err = tracehandler.Start(ctx, containerMetadataHandler, rep,
		trc.TraceProcessor(), traceCh, times)
	return err
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	args, err := parseArgs()
	if err != nil {
		return parseError("Failure to parse arguments: %v", err)
	}

	if args.copyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	if args.version {
		fmt.Printf("%s\n", vc.Version())
		return exitSuccess
	}

	if args.verboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		args.dump()
	}

	if code := sanityCheck(args); code != exitSuccess {
		return code
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if args.pprofAddr != "" {
		go func() {
			//nolint:gosec
			if err = http.ListenAndServe(args.pprofAddr, nil); err != nil {
				log.Errorf("Serving pprof on %s failed: %s", args.pprofAddr, err)
			}
		}()
	}

	startTime := time.Now()
	log.Infof("Starting OTEL profiling agent %s (revision %s, build timestamp %s)",
		vc.Version(), vc.Revision(), vc.BuildTimestamp())

	environment, err := env.NewEnvironment(args.environmentType, args.machineID)
	if err != nil {
		log.Errorf("Failed to create environment: %v", err)
		return exitFailure
	}

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return failure(fmt.Sprintf("Failed to probe eBPF syscall: %v", err))
	}

	if err = tracer.ProbeTracepoint(); err != nil {
		return failure("Failed to probe tracepoint: %v", err)
	}

	hostmeta.SetTags(args.tags)

	var presentCores uint16
	presentCores, err = hostmeta.PresentCPUCores()
	if err != nil {
		return failure("Failed to read CPU file: %v", err)
	}

	// Retrieve host metadata that will be stored with the HA config, and
	// sent to the backend with certain RPCs.
	hostMetadataMap := make(map[string]string)
	if err = hostmeta.AddMetadata(args.collAgentAddr, hostMetadataMap); err != nil {
		log.Errorf("Unable to get host metadata for config: %v", err)
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
		Version:                vc.Version(),
		Revision:               vc.Revision(),
		BuildTimestamp:         vc.BuildTimestamp(),
		ProjectID:              uint32(args.projectID),
		CacheDirectory:         args.cacheDirectory,
		SecretToken:            args.secretToken,
		Tags:                   args.tags,
		Tracers:                args.tracers,
		Verbose:                args.verboseMode,
		DisableTLS:             args.disableTLS,
		NoKernelVersionCheck:   args.noKernelVersionCheck,
		BpfVerifierLogLevel:    args.bpfVerifierLogLevel,
		BpfVerifierLogSize:     args.bpfVerifierLogSize,
		MonitorInterval:        args.monitorInterval,
		ReportInterval:         args.reporterInterval,
		SamplesPerSecond:       uint16(args.samplesPerSecond),
		CollectionAgentAddr:    args.collAgentAddr,
		ConfigurationFile:      args.configFile,
		PresentCPUCores:        presentCores,
		TraceCacheIntervals:    6,
		MapScaleFactor:         uint8(args.mapScaleFactor),
		StartTime:              startTime,
		IPAddress:              hostMetadataMap[hostmeta.KeyIPAddress],
		Hostname:               hostMetadataMap[hostmeta.KeyHostname],
		KernelVersion:          hostMetadataMap[hostmeta.KeyKernelVersion],
		ProbabilisticInterval:  args.probabilisticInterval,
		ProbabilisticThreshold: args.probabilisticThreshold,
	}
	if err = config.SetConfiguration(&conf); err != nil {
		return failure("Failed to set configuration: %v", err)
	}

	// Start periodic synchronization of monotonic clock
	config.StartMonotonicSync(mainCtx)
	log.Debugf("Done setting configuration")

	times := config.GetTimes()

	log.Debugf("Determining tracers to include")
	includeTracers, err := config.ParseTracers(args.tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %s", err)
	}

	log.Infof("Assigned ProjectID: %d HostID: %d", config.ProjectID(), config.HostID())

	// Scale the queues that report traces or information related to traces
	// with the number of CPUs, the reporting interval and the sample frequencies.
	tracesQSize := max(1024,
		uint32(runtime.NumCPU()*int(args.reporterInterval.Seconds()*2)*args.samplesPerSecond))

	metadataCollector := hostmetadata.NewCollector(args.collAgentAddr, environment)

	// TODO: Maybe abort execution if (some) metadata can not be collected
	hostMetadataMap = metadataCollector.GetHostMetadata()

	if bpfJITEnabled, found := hostMetadataMap["host.sysctl.net.core.bpf_jit_enable"]; found {
		if bpfJITEnabled == "0" {
			log.Warnf("The BPF JIT is disabled (net.core.bpf_jit_enable = 0). " +
				"Enable it to reduce CPU overhead.")
		}
	}

	// Network operations to CA start here
	var rep reporter.Reporter
	// Connect to the collection agent
	rep, err = reporter.Start(mainCtx, &reporter.Config{
		CollAgentAddr:           args.collAgentAddr,
		MaxRPCMsgSize:           33554432, // 32 MiB
		ExecMetadataMaxQueue:    2048,
		CountsForTracesMaxQueue: tracesQSize,
		MetricsMaxQueue:         1024,
		FramesForTracesMaxQueue: tracesQSize,
		FrameMetadataMaxQueue:   tracesQSize,
		HostMetadataMaxQueue:    2,
		FallbackSymbolsMaxQueue: 1024,
		DisableTLS:              args.disableTLS,
		MaxGRPCRetries:          5,
		Times:                   times,
	})
	if err != nil {
		return failure("Failed to start reporting: %v", err)
	}

	metrics.SetReporter(rep)

	// Now that we've sent the first host metadata update, start a goroutine to keep sending updates
	// regularly. This is required so pf-web-service only needs to query metadata for bounded
	// periods of time.
	metadataCollector.StartMetadataCollection(mainCtx, rep)

	// Start agent specific metric retrieval and report them every second.
	agentMetricCancel, agentErr := agentmetrics.Start(mainCtx, 1*time.Second)
	if agentErr != nil {
		return failure("Error starting the agent specific metric collection: %v", agentErr)
	}
	defer agentMetricCancel()
	// Start reporter metric reporting with 60 second intervals.
	defer reportermetrics.Start(mainCtx, rep, 60*time.Second)()

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, rep, times, includeTracers, !args.sendErrorFrames)
	if err != nil {
		return failure("Failed to load eBPF tracer: %v", err)
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	// Initial scan of /proc filesystem to list currently-active PIDs and have them processed.
	if err = trc.StartPIDEventProcessor(mainCtx); err != nil {
		log.Errorf("Failed to list processes from /proc: %v", err)
	}
	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(args.samplesPerSecond); err != nil {
		return failure("Failed to attach to perf event: %v", err)
	}
	log.Info("Attached tracer program")

	if args.probabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx,
			args.probabilisticInterval, args.probabilisticThreshold)
		log.Printf("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return failure("Failed to enable perf events: %v", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return failure("Failed to attach scheduler monitor: %v", err)
	}

	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	log.Printf("Attached sched monitor")

	if err := startTraceHandling(mainCtx, rep, times, trc); err != nil {
		return failure("Failed to start trace handling: %v", err)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return exitSuccess
}

func sanityCheck(args *arguments) exitCode {
	if args.environmentType == "" && args.machineID != "" {
		return parseError("You can only specify the machine ID if you also provide the environment")
	}

	if args.mapScaleFactor > 8 {
		return parseError("eBPF map scaling factor %d exceeds limit (max: %d)",
			args.mapScaleFactor, maxArgMapScaleFactor)
	}

	if args.bpfVerifierLogLevel > 2 {
		return parseError("Invalid eBPF verifier log level: %d", args.bpfVerifierLogLevel)
	}

	if args.probabilisticInterval < 1*time.Minute || args.probabilisticInterval > 5*time.Minute {
		return parseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if args.probabilisticThreshold < 1 ||
		args.probabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return parseError("Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
	}

	if !args.noKernelVersionCheck {
		major, minor, patch, err := tracer.GetCurrentKernelVersion()
		if err != nil {
			return failure("Failed to get kernel version: %v", err)
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
			return failure("Unsupported architecture: %s", runtime.GOARCH)
		}

		if major < minMajor || (major == minMajor && minor < minMinor) {
			return failure("Host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
		}
	}

	return exitSuccess
}

func parseError(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitParseError
}

func failure(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
