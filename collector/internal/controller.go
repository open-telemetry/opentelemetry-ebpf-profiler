// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.uber.org/zap"

	hostinfo "go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var (
	agentShutdown = func() {}
)

type Controller struct {
	host         component.Host
	cancel       context.CancelFunc
	logger       *zap.Logger
	nextConsumer consumerprofiles.Profiles
	config       *Config
}

func NewController(logger *zap.Logger, nextConsumer consumerprofiles.Profiles,
	cfg *Config) *Controller {
	return &Controller{
		logger:       logger,
		nextConsumer: nextConsumer,
		config:       cfg,
	}
}

// Start starts the receiver.
func (c *Controller) Start(ctx context.Context, host component.Host) error {
	cfg := c.config

	if cfg.Verbose {
		// logrus is used in the agent code, so we need to set the log level here.
		// todo: make the logger configurable
		logrus.SetLevel(logrus.DebugLevel)
	}

	log := c.logger.Sugar()

	c.host = host
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, c.cancel = context.WithCancel(ctx)

	if err := tracer.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %v", err)
	}

	if err := tracer.ProbeTracepoint(); err != nil {
		return fmt.Errorf("failed to probe tracepoint: %v", err)
	}

	log.Debug("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(cfg.Tracers)
	if err != nil {
		return fmt.Errorf("failed to parse the included tracers: %v", err)
	}

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get Linux kernel version: %v", err)
	}

	intervals := times.New(cfg.MonitorInterval, cfg.ReporterInterval, cfg.ProbabilisticInterval)

	traceHandlerCacheSize :=
		traceCacheSize(cfg.MonitorInterval, cfg.SamplesPerSecond, cfg.PresentCPUCores)

	log.Debugf("Collection agent: %s", cfg.CollectionAgent)

	// hostname and sourceIP will be populated from the root namespace.
	var hostname, sourceIP string

	if err = runInRootNS(func() error {
		var hostnameErr error
		hostname, hostnameErr = os.Hostname()
		if hostnameErr != nil {
			return fmt.Errorf("failed to get hostname: %v", hostnameErr)
		}

		srcIP, ipErr := getSourceIPAddress(cfg.CollectionAgent)
		if ipErr != nil {
			return fmt.Errorf("failed to get source IP: %v", ipErr)
		}
		sourceIP = srcIP.String()
		return nil
	}); err != nil {
		log.Warnf("Failed to fetch metadata information in the root namespace: %v", err)
	}

	// Connect to the collection agent and start reporting.
	rep, err := reporter.Start(ctx, &reporter.Config{
		CollAgentAddr:          cfg.CollectionAgent,
		DisableTLS:             cfg.DisableTLS,
		MaxRPCMsgSize:          32 << 20, // 32 MiB
		MaxGRPCRetries:         5,
		GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
		ReportInterval:         intervals.ReportInterval(),
		CacheSize:              traceHandlerCacheSize,
		SamplesPerSecond:       cfg.SamplesPerSecond,
		HostID:                 cfg.HostID,
		KernelVersion:          kernelVersion,
		HostName:               hostname,
		IPAddress:              sourceIP,
	})
	if err != nil {
		return fmt.Errorf("failed to start reporting: %v", err)
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !cfg.SendErrorFrames,
		SamplesPerSecond:       cfg.SamplesPerSecond,
		MapScaleFactor:         int(cfg.MapScaleFactor),
		KernelVersionCheck:     !cfg.NoKernelVersionCheck,
		BPFVerifierLogLevel:    uint32(cfg.BpfVerifierLogLevel),
		ProbabilisticInterval:  cfg.ProbabilisticInterval,
		ProbabilisticThreshold: cfg.ProbabilisticThreshold,
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %v", err)
	}
	log.Info("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	// Initial scan of /proc filesystem to list currently active PIDs and have them processed.
	if err = trc.StartPIDEventProcessor(ctx); err != nil {
		log.Errorf("Failed to list processes from /proc: %v", err)
	}
	log.Debugf("Completed initial PID listing after %dms", time.Since(now).Milliseconds())

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return fmt.Errorf("failed to attach to perf event: %v", err)
	}
	log.Info("Attached tracer program")

	if cfg.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(ctx)
		log.Info("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return fmt.Errorf("failed to enable perf events: %v", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %v", err)
	}

	// This log line is used in our system tests to verify if that the agent has started.
	// So if you change this log line, update also the system test.
	log.Info("Attached sched monitor")
	log.Infof("cfg: %+v", cfg)
	log.Info("intervals: ", intervals)

	if err := startTraceHandling(ctx, rep, intervals, trc, traceHandlerCacheSize); err != nil {
		return fmt.Errorf("failed to start trace handling: %v", err)
	}

	go func() {
		// Wait until the receiver should terminate.
		<-ctx.Done()

		log.Info("Stop processing ...")
		rep.Stop()

		log.Info("Exiting ...")
	}()

	return nil
}

// Shutdown stops the receiver.
func (c *Controller) Shutdown(_ context.Context) error {
	agentShutdown()
	c.cancel()
	return nil
}

func startTraceHandling(ctx context.Context, rep reporter.TraceReporter,
	intervals *times.Times, trc *tracer.Tracer, cacheSize uint32) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *hostinfo.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	_, err := tracehandler.Start(ctx, rep, trc.TraceProcessor(), traceCh, intervals, cacheSize)
	return err
}

// traceCacheSize defines the maximum number of elements for the caches in tracehandler.
//
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit/cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g., too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here.
func traceCacheSize(monitorInterval time.Duration, samplesPerSecond, presentCPUCores int) uint32 {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)

	maxElementsPerInterval := samplesPerSecond * int(monitorInterval.Seconds()) * presentCPUCores

	size := maxElementsPerInterval * traceCacheIntervals
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(uint32(size))
}
