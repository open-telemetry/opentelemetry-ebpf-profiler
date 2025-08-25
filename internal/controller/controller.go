package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tklauser/numcpus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const MiB = 1 << 20

// Controller is an instance that runs, manages and stops the agent.
type Controller struct {
	config   *Config
	reporter reporter.Reporter
	tracer   *tracer.Tracer
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
func (c *Controller) Start(ctx context.Context) error {
	if err := tracer.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		return fmt.Errorf("failed to read CPU file: %w", err)
	}

	traceHandlerCacheSize :=
		traceCacheSize(c.config.MonitorInterval, c.config.SamplesPerSecond, uint16(presentCores))

	intervals := times.New(c.config.ReporterInterval, c.config.MonitorInterval,
		c.config.ProbabilisticInterval)

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
	splittedEnvVars := strings.Split(c.config.IncludeEnvVars, ",")
	for _, envVar := range splittedEnvVars {
		envVar = strings.TrimSpace(envVar)
		if envVar != "" {
			envVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !c.config.SendErrorFrames,
		SamplesPerSecond:       c.config.SamplesPerSecond,
		MapScaleFactor:         int(c.config.MapScaleFactor),
		KernelVersionCheck:     !c.config.NoKernelVersionCheck,
		VerboseMode:            c.config.VerboseMode,
		BPFVerifierLogLevel:    uint32(c.config.BpfVerifierLogLevel),
		ProbabilisticInterval:  c.config.ProbabilisticInterval,
		ProbabilisticThreshold: c.config.ProbabilisticThreshold,
		OffCPUThreshold:        uint32(c.config.OffCPUThreshold * float64(math.MaxUint32)),
		IncludeEnvVars:         envVars,
		UProbeLinks:            c.config.UProbeLinks,
		LoadProbe:              c.config.LoadProbe,
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}
	c.tracer = trc
	log.Printf("eBPF tracer loaded")

	now := time.Now()

	trc.StartPIDEventProcessor(ctx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return fmt.Errorf("failed to attach to perf event: %w", err)
	}
	log.Info("Attached tracer program")

	if c.config.OffCPUThreshold > 0.0 {
		if err := trc.StartOffCPUProfiling(); err != nil {
			return fmt.Errorf("failed to start off-cpu profiling: %v", err)
		}
		log.Printf("Enabled off-cpu profiling with p=%f", c.config.OffCPUThreshold)
	}

	if len(c.config.UProbeLinks) > 0 {
		if err := trc.AttachUProbes(c.config.UProbeLinks); err != nil {
			return fmt.Errorf("failed to attach uprobes: %v", err)
		}
		log.Printf("Attached uprobes")
	}

	if c.config.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(ctx)
		log.Printf("Enabled probabilistic profiling")
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
	log.Printf("Attached sched monitor")

	if err := startTraceHandling(ctx, c.reporter, intervals, trc,
		traceHandlerCacheSize); err != nil {
		return fmt.Errorf("failed to start trace handling: %w", err)
	}

	return nil
}

// Shutdown stops the controller
func (c *Controller) Shutdown() {
	log.Info("Stop processing ...")
	if c.reporter != nil {
		c.reporter.Stop()
	}

	if c.tracer != nil {
		c.tracer.Close()
	}
}

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

	size := max(maxElements*uint32(traceCacheIntervals), traceCacheMinSize)
	return util.NextPowerOfTwo(size)
}

func maxElementsPerInterval(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	return uint32(uint16(samplesPerSecond) * uint16(monitorInterval.Seconds()) * presentCPUCores)
}
