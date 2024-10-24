// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"

	//nolint:gosec
	_ "net/http/pprof"
	"os"
	"os/signal"
	"time"

	"github.com/tklauser/numcpus"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/helpers"
	"go.opentelemetry.io/ebpf-profiler/times"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
	"go.opentelemetry.io/ebpf-profiler/vc"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"

	"go.opentelemetry.io/ebpf-profiler/hostmetadata"

	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"

	"go.opentelemetry.io/ebpf-profiler/tracer"

	log "github.com/sirupsen/logrus"
)

// Short copyright / license text for eBPF code
var copyright = `Copyright The OpenTelemetry Authors.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). You can obtain a copy of the GPLv2 code at:
https://go.opentelemetry.io/ebpf-profiler/tree/main/support/ebpf

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

	_, err := tracehandler.Start(ctx, rep, trc.TraceProcessor(),
		traceCh, intervals, cacheSize)
	return err
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	cfg, err := parseArgs()
	if err != nil {
		log.Errorf("Failure to parse arguments: %v", err)
		return exitParseError
	}

	if cfg.Copyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	if cfg.Version {
		fmt.Printf("%s\n", vc.Version())
		return exitSuccess
	}

	if cfg.VerboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		cfg.Dump()
	}

	if err = cfg.Validate(); err != nil {
		log.Error(err)
		return exitFailure
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if cfg.PprofAddr != "" {
		go func() {
			//nolint:gosec
			if err = http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
				log.Errorf("Serving pprof on %s failed: %s", cfg.PprofAddr, err)
			}
		}()
	}

	log.Infof("Starting OTEL profiling agent %s (revision %s, build timestamp %s)",
		vc.Version(), vc.Revision(), vc.BuildTimestamp())

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return failure("Failed to probe eBPF syscall: %v", err)
	}

	if err = tracer.ProbeTracepoint(); err != nil {
		return failure("Failed to probe tracepoint: %v", err)
	}

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		return failure("Failed to read CPU file: %v", err)
	}

	traceHandlerCacheSize :=
		traceCacheSize(cfg.MonitorInterval, cfg.SamplesPerSecond, uint16(presentCores))

	intervals := times.New(cfg.MonitorInterval,
		cfg.ReporterInterval, cfg.ProbabilisticInterval)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, cfg.ClockSyncInterval)

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(cfg.Tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %v", err)
	}

	metadataCollector := hostmetadata.NewCollector(cfg.CollAgentAddr)
	metadataCollector.AddCustomData("os.type", "linux")

	kernelVersion, err := helpers.GetKernelVersion()
	if err != nil {
		return failure("Failed to get Linux kernel version: %v", err)
	}
	// OTel semantic introduced in https://github.com/open-telemetry/semantic-conventions/issues/66
	metadataCollector.AddCustomData("os.kernel.release", kernelVersion)

	// hostname and sourceIP will be populated from the root namespace.
	hostname, sourceIP, err := helpers.GetHostnameAndSourceIP(cfg.CollAgentAddr)
	if err != nil {
		log.Warnf("Failed to fetch metadata information in the root namespace: %v", err)
	}
	metadataCollector.AddCustomData("host.name", hostname)
	metadataCollector.AddCustomData("host.ip", sourceIP)

	// Network operations to CA start here
	var rep reporter.Reporter
	// Connect to the collection agent
	rep, err = reporter.Start(mainCtx, &reporter.Config{
		CollAgentAddr:          cfg.CollAgentAddr,
		DisableTLS:             cfg.DisableTLS,
		MaxRPCMsgSize:          32 << 20, // 32 MiB
		MaxGRPCRetries:         5,
		GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
		ReportInterval:         intervals.ReportInterval(),
		CacheSize:              traceHandlerCacheSize,
		SamplesPerSecond:       cfg.SamplesPerSecond,
		KernelVersion:          kernelVersion,
		HostName:               hostname,
		IPAddress:              sourceIP,
	})
	if err != nil {
		return failure("Failed to start reporting: %v", err)
	}

	metrics.SetReporter(rep)

	// Now that set the initial host metadata, start a goroutine to keep sending updates regularly.
	metadataCollector.StartMetadataCollection(mainCtx, rep)

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !cfg.SendErrorFrames,
		SamplesPerSecond:       cfg.SamplesPerSecond,
		MapScaleFactor:         int(cfg.MapScaleFactor),
		KernelVersionCheck:     !cfg.NoKernelVersionCheck,
		DebugTracer:            cfg.VerboseMode,
		BPFVerifierLogLevel:    uint32(cfg.BpfVerifierLogLevel),
		ProbabilisticInterval:  cfg.ProbabilisticInterval,
		ProbabilisticThreshold: cfg.ProbabilisticThreshold,
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

	if cfg.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
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

func failure(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
