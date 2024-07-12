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
	"strconv"
	"time"

	//nolint:gosec
	_ "net/http/pprof"

	"github.com/elastic/otel-profiling-agent/containermetadata"
	agentmeta "github.com/elastic/otel-profiling-agent/hostmetadata/agent"
	"github.com/elastic/otel-profiling-agent/platform"
	"github.com/elastic/otel-profiling-agent/times"
	tracertypes "github.com/elastic/otel-profiling-agent/tracer/types"
	"github.com/elastic/otel-profiling-agent/util"
	"github.com/elastic/otel-profiling-agent/vc"
	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/host"
	hostmeta "github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/tracehandler"

	"github.com/elastic/otel-profiling-agent/hostmetadata"
	"github.com/elastic/otel-profiling-agent/metrics/reportermetrics"

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
	intervals *times.Times, trc *tracer.Tracer, cacheSize uint32) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	containerMetadataHandler, err := containermetadata.GetHandler(ctx, intervals.MonitorInterval())
	if err != nil {
		return fmt.Errorf("failed to create container metadata handler: %v", err)
	}

	_, err = tracehandler.Start(ctx, containerMetadataHandler, rep,
		trc.TraceProcessor(), traceCh, intervals, cacheSize)
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

	if err = mkCacheDirectory(args.cacheDirectory); err != nil {
		failure("%v", err)
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

	environment, err := platform.NewEnvironment(args.environmentType, args.machineID)
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

	var presentCores uint16
	presentCores, err = hostmeta.PresentCPUCores()
	if err != nil {
		return failure("Failed to read CPU file: %v", err)
	}

	traceHandlerCacheSize :=
		traceCacheSize(args.monitorInterval, args.samplesPerSecond, presentCores)

	agentmeta.SetAgentData(&agentmeta.Config{
		Version:                vc.Version(),
		Revision:               vc.Revision(),
		BuildTimestamp:         vc.BuildTimestamp(),
		StartTime:              startTime,
		CacheDirectory:         args.cacheDirectory,
		CollectionAgentAddr:    args.collAgentAddr,
		ConfigurationFile:      args.configFile,
		Tags:                   args.tags,
		Tracers:                args.tracers,
		Verbose:                args.verboseMode,
		DisableTLS:             args.disableTLS,
		NoKernelVersionCheck:   args.noKernelVersionCheck,
		BpfVerifierLogLevel:    args.bpfVerifierLogLevel,
		BpfVerifierLogSize:     args.bpfVerifierLogSize,
		MapScaleFactor:         args.mapScaleFactor,
		ProbabilisticInterval:  args.probabilisticInterval,
		ProbabilisticThreshold: args.probabilisticThreshold,
		PresentCPUCores:        presentCores,
		TraceCacheEntries:      traceHandlerCacheSize,
		MaxElementsPerInterval: maxElementsPerInterval(args.monitorInterval, args.samplesPerSecond,
			presentCores),
		EnvHTTPSProxy: os.Getenv("HTTPS_PROXY"),
	})
	hostmeta.SetTags(args.tags)

	// Retrieve host metadata that will be stored with the HA config, and
	// sent to the backend with certain RPCs.
	hostMetadataMap := make(map[string]string)
	if err = hostmeta.AddMetadata(hostMetadataMap); err != nil {
		log.Errorf("Unable to get host metadata for config: %v", err)
	}

	intervals := times.New(mainCtx,
		args.monitorInterval, args.reporterInterval, args.probabilisticInterval)

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(args.tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %v", err)
	}

	log.Infof("Assigned ProjectID: %d HostID: %d", args.projectID, environment.HostID())

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
		GRPCOperationTimeout:    intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime:  intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:   intervals.GRPCConnectionTimeout(),
		ReportInterval:          intervals.ReportInterval(),
		CacheSize:               traceHandlerCacheSize,
		SamplesPerSecond:        args.samplesPerSecond,
		ProjectID:               strconv.Itoa(int(args.projectID)),
		HostID:                  environment.HostID(),
		KernelVersion:           hostMetadataMap[hostmeta.KeyKernelVersion],
		HostName:                hostMetadataMap[hostmeta.KeyHostname],
		IPAddress:               hostMetadataMap[hostmeta.KeyIPAddress],
	})
	if err != nil {
		return failure("Failed to start reporting: %v", err)
	}

	metrics.SetReporter(rep)

	// Set the initial host metadata.
	rep.ReportHostMetadata(hostMetadataMap)

	// Now that set the initial host metadata, start a goroutine to keep sending updates regularly.
	metadataCollector.StartMetadataCollection(mainCtx, rep)

	// Start agent-specific metric retrieval and report them every second.
	agentMetricCancel, agentErr := agentmetrics.Start(mainCtx, 1*time.Second)
	if agentErr != nil {
		return failure("Error starting the agent specific metric collection: %v", agentErr)
	}
	defer agentMetricCancel()
	// Start reporter metric reporting with 60 second intervals.
	defer reportermetrics.Start(mainCtx, rep, 60*time.Second)()

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !args.sendErrorFrames,
		SamplesPerSecond:       args.samplesPerSecond,
		MapScaleFactor:         int(args.mapScaleFactor),
		KernelVersionCheck:     !args.noKernelVersionCheck,
		BPFVerifierLogLevel:    uint32(args.bpfVerifierLogLevel),
		BPFVerifierLogSize:     args.bpfVerifierLogSize,
		ProbabilisticInterval:  args.probabilisticInterval,
		ProbabilisticThreshold: args.probabilisticThreshold,
	})
	if err != nil {
		return failure("Failed to load eBPF tracer: %v", err)
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	// Initial scan of /proc filesystem to list currently active PIDs and have them processed.
	if err = trc.StartPIDEventProcessor(mainCtx); err != nil {
		log.Errorf("Failed to list processes from /proc: %v", err)
	}
	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return failure("Failed to attach to perf event: %v", err)
	}
	log.Info("Attached tracer program")

	if args.probabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx)
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

	if err := startTraceHandling(mainCtx, rep, intervals, trc, traceHandlerCacheSize); err != nil {
		return failure("Failed to start trace handling: %v", err)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return exitSuccess
}

// traceCacheSize defines the maximum number of elements for the caches in tracehandler.
//
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit:cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g. too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here.
func traceCacheSize(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)

	maxElements := maxElementsPerInterval(monitorInterval, samplesPerSecond, presentCPUCores)

	size := maxElements * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(size)
}

func maxElementsPerInterval(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	return uint32(uint16(samplesPerSecond) * uint16(monitorInterval.Seconds()) * presentCPUCores)
}

func mkCacheDirectory(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Debugf("Creating cache directory '%s'", dir)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create cache directory (%s): %v", dir, err)
		}
	}
	return nil
}

func sanityCheck(args *arguments) exitCode {
	if args.environmentType == "" && args.machineID != "" {
		return parseError("You can only specify the machine ID if you also provide the environment")
	}

	if args.samplesPerSecond < 1 {
		return parseError("Invalid sampling frequency: %d", args.samplesPerSecond)
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
			minMajor, minMinor = 4, 19
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
