package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const MiB = 1 << 20

// Controller is an instance that runs, manages and stops the agent.
type Controller struct {
	config   *Config
	reporter reporter.Reporter
	tracer   *tracer.Tracer

	shutdownOnceFn sync.Once
	cancelFunc     context.CancelFunc
}

// New creates a new controller
// The controller can set global configurations (such as the eBPF syscalls) on
// setup. So there should only ever be one running.
func New(cfg *Config) *Controller {
	c := &Controller{
		config:   cfg,
		reporter: cfg.Reporter,
	}

	return c
}

// Start starts the controller
// The controller should only be started once.
//
// Lifecycle note:
// This controller is expected to be started by the OpenTelemetry Collector
// service. If Start returns an error (for example, if StartMapMonitors fails),
// collector startup is aborted and the collector will immediately invoke
// Shutdown on all started services.
//
// In other words, partial initialization performed by Start does not require
// explicit cleanup on error here: the collector guarantees that Shutdown(ctx)
// will be called as part of its startup error handling path.
//
// See:
// https://github.com/open-telemetry/opentelemetry-collector/blob/v0.144.0/otelcol/collector.go#L258-L260
func (c *Controller) Start(ctx context.Context) error {
	if err := linux.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}

	intervals := times.New(c.config.ReporterInterval, c.config.MonitorInterval,
		c.config.ProbabilisticInterval)

	ctx, c.cancelFunc = context.WithCancel(ctx)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(ctx, c.config.ClockSyncInterval)

	err := c.reporter.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start reporter: %w", err)
	}

	envVars := libpf.Set[string]{}
	for envVar := range strings.SplitSeq(c.config.IncludeEnvVars, ",") {
		envVar = strings.TrimSpace(envVar)
		if envVar != "" {
			envVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:           c.reporter,
		Intervals:               intervals,
		InterpretersConfig:      c.config.Interpreters,
		FilterErrorFrames:       !c.config.SendErrorFrames,
		FilterIdleFrames:        !c.config.SendIdleFrames,
		FilterMinProcessAge:     c.config.FilterMinProcessAge,
		SamplesPerSecond:        c.config.SamplesPerSecond,
		MapScaleFactor:          int(c.config.MapScaleFactor),
		FrameCacheSize:          uint32(c.config.FrameCacheSize),
		KernelVersionCheck:      !c.config.NoKernelVersionCheck,
		VerboseMode:             c.config.VerboseMode,
		BPFVerifierLogLevel:     uint32(c.config.BPFVerifierLogLevel),
		ProbabilisticInterval:   c.config.ProbabilisticInterval,
		ProbabilisticThreshold:  c.config.ProbabilisticThreshold,
		IncludeEnvVars:          envVars,
		ExecutableReporter:      c.config.ExecutableReporter,
		BPFFSRoot:               c.config.BPFFSRoot,
		OBIProcessCtx:           c.config.OBIProcessCtx,
		PIDNamespaceTranslation: c.config.PIDNamespaceTranslation,
		ProcessMetaEnrichers:    c.config.ProcessMetaEnrichers,
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}
	c.tracer = trc
	log.Info("eBPF tracer loaded")

	now := time.Now()

	trc.StartPIDEventProcessor(ctx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(c.config.PinnedCPUIDs); err != nil {
		return fmt.Errorf("failed to attach to perf event: %w", err)
	}
	log.Info("Attached tracer program")

	if c.config.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(ctx)
		log.Info("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return fmt.Errorf("failed to enable perf events: %w", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %w", err)
	}

	// This log line is used in our system tests to verify if that the agent has started.
	// So if you change this log line update also the system test.
	log.Info("Attached sched monitor")

	// A missing prctl monitor only delays discovery of process context mappings;
	// core profiling is unaffected, so warn and continue rather than aborting.
	if err := trc.AttachPrctlMonitor(); err != nil {
		log.Warnf("Failed to attach prctl monitor: %v", err)
	} else {
		log.Info("Attached prctl monitor")
	}

	if err := c.startTraceHandling(ctx, trc); err != nil {
		return fmt.Errorf("failed to start trace handling: %w", err)
	}

	return nil
}

// Shutdown stops the controller
func (c *Controller) Shutdown() {
	c.shutdownOnceFn.Do(func() {
		log.Info("Stop processing ...")
		if c.cancelFunc != nil {
			c.cancelFunc()
		}

		if c.reporter != nil {
			c.reporter.Stop()
		}

		if c.tracer != nil {
			c.tracer.Close()
		}
	})
}

// EnableProbe enables a probe on the running tracer. It must be called after
// Start has completed. The probe requires the kprobe unwinder chain, which is
// loaded automatically when probes is non-empty in the config.
func (c *Controller) EnableProbe(ctx context.Context, p tracer.Probe) error {
	return c.tracer.Enable(ctx, p)
}

func (c *Controller) startTraceHandling(ctx context.Context, trc *tracer.Tracer) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *libpf.EbpfTrace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	go func() {
		// Poll the output channels
		for {
			select {
			case trace := <-traceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-trc.Done():
				log.Errorf("Shutting down controller due to unrecoverable tracer error")
				c.Shutdown()
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}
