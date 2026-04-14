package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/probes/offcpu"
	"go.opentelemetry.io/ebpf-profiler/probes/oom"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
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

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(c.config.Tracers)
	if err != nil {
		return fmt.Errorf("failed to parse the included tracers: %w", err)
	}

	err = c.reporter.Start(ctx)
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
		TraceReporter:          c.reporter,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !c.config.SendErrorFrames,
		FilterIdleFrames:       !c.config.SendIdleFrames,
		SamplesPerSecond:       c.config.SamplesPerSecond,
		MapScaleFactor:         int(c.config.MapScaleFactor),
		KernelVersionCheck:     !c.config.NoKernelVersionCheck,
		VerboseMode:            c.config.VerboseMode,
		BPFVerifierLogLevel:    uint32(c.config.BPFVerifierLogLevel),
		ProbabilisticInterval:  c.config.ProbabilisticInterval,
		ProbabilisticThreshold: c.config.ProbabilisticThreshold,
		IncludeEnvVars:         envVars,
		// ProbeLinks:             c.config.ProbeLinks, // Replaced by c.config.CustomProbes
		LoadProbe:          c.config.LoadProbe || len(c.config.CustomProbes) != 0,
		ExecutableReporter: c.config.ExecutableReporter,
		BPFFSRoot:          c.config.BPFFSRoot,
		OBIProcessCtx:      c.config.OBIProcessCtx,
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
	if err := trc.AttachTracer(); err != nil {
		return fmt.Errorf("failed to attach to perf event: %w", err)
	}
	log.Info("Attached tracer program")

	//	if c.config.OffCPUThreshold > 0.0 {
	//		if err := trc.StartOffCPUProfiling(); err != nil {
	//			return fmt.Errorf("failed to start off-cpu profiling: %v", err)
	//		}
	//		log.Infof("Enabled off-cpu profiling with p=%f", c.config.OffCPUThreshold)
	//	}

	// if len(c.config.ProbeLinks) > 0 {
	// 	if err := trc.AttachProbes(c.config.ProbeLinks); err != nil {
	// 		return fmt.Errorf("failed to attach probes: %v", err)
	// 	}
	// 	log.Info("Attached probes")
	// }

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

	if err := c.startTraceHandling(ctx, trc); err != nil {
		return fmt.Errorf("failed to start trace handling: %w", err)
	}

	if err := c.enableCustomProbes(trc); err != nil {
		return fmt.Errorf("failed to enable custom probes: %w", err)
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

func (c *Controller) enableCustomProbes(trc *tracer.Tracer) error {
	if len(c.config.CustomProbes) == 0 {
		return nil
	}

	for probeName, probeConfig := range c.config.CustomProbes {
		probe, err := createCustomProbe(probeName, probeConfig)
		if err != nil {
			return fmt.Errorf("failed to create custom probe %q: %w", probeName, err)
		}

		if err := trc.Enable(probe); err != nil {
			return fmt.Errorf("failed to enable custom probe %q: %w", probeName, err)
		}

		log.Infof("Enabled custom probe %q", probeName)
	}

	return nil
}

func createCustomProbe(name string, cfg any) (tracer.Probe, error) {
	switch name {
	case "oom":
		return oom.New(cfg)
	case "offcpu":
		return offcpu.New(cfg)
	default:
		return nil, fmt.Errorf("unknown custom probe: %q", name)
	}
}
