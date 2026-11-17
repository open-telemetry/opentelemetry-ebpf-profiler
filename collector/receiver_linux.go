// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// profilesReceiver implements [xreceiver.Profiles] and runs the eBPF profiler.
type profilesReceiver struct {
	cfg  *config.Config
	opts *controllerOption

	intervals *times.Times
	reporter  reporter.Reporter
	tracer    *tracer.Tracer
	probes    []tracer.Probe

	cancelFunc     context.CancelFunc
	shutdownOnceFn sync.Once
}

func newProfilesReceiver(cfg *config.Config, opts *controllerOption, rs receiver.Settings,
	nextConsumer xconsumer.Profiles,
) (*profilesReceiver, error) {
	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)

	reporterFactory := opts.reporterFactory
	if reporterFactory == nil {
		reporterFactory = func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error) {
			return reporter.NewCollector(cfg, nextConsumer)
		}
	}

	rep, err := reporterFactory(&reporter.Config{
		Name:           metadata.ScopeName,
		Version:        moduleVersion(rs.BuildInfo.Version),
		ReportInterval: intervals.ReportInterval(),
		ReportJitter:   cfg.ReporterJitter,
	}, nextConsumer)
	if err != nil {
		return nil, err
	}

	// Provide internal metrics via the collectors telemetry.
	meter := rs.MeterProvider.Meter(metadata.ScopeName)
	metrics.Start(meter)

	return &profilesReceiver{
		cfg:       cfg,
		opts:      opts,
		intervals: intervals,
		reporter:  rep,
	}, nil
}

// moduleVersion returns the profiler module's own version from the Go module graph.
// Falls back to the collector's build version (e.g. set by ocb) if the
// module isn't found, which happens when built outside of a real module context.
func moduleVersion(fallback string) string {
	version := fallback
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for i := range buildInfo.Deps {
			dep := buildInfo.Deps[i]
			if dep.Path == metadata.ScopeName {
				// dep.Version reflects the required directive and stays set to the original
				// version even when a replace directive redirects the module. Therefore use the
				// replacement's actual version instead.
				if dep.Replace != nil {
					version = dep.Replace.Version
				} else {
					version = dep.Version
				}
			}
		}
	}
	return version
}

// Start the receiver.
//
// Lifecycle note:
// If Start returns an error (for example, if StartMapMonitors fails),
// collector startup is aborted and the collector will immediately invoke
// Shutdown on all started components.
//
// In other words, partial initialization performed by Start does not require
// explicit cleanup on error here: the collector guarantees that Shutdown(ctx)
// will be called as part of its startup error handling path.
//
// See:
// https://github.com/open-telemetry/opentelemetry-collector/blob/v0.144.0/otelcol/collector.go#L258-L260
func (r *profilesReceiver) Start(ctx context.Context, host component.Host) error {
	if err := r.startProfiler(ctx); err != nil {
		if r.cfg.ErrorMode == config.IgnoreError {
			r.Shutdown(ctx)
			log.Errorf("eBPF profiler receiver failed, continuing without profiling: %v", err)
			return nil
		}
		return err
	}

	if err := r.enableProbes(ctx, host); err != nil {
		if r.cfg.ErrorMode == config.IgnoreError {
			r.Shutdown(ctx)
			log.Errorf("Failed to enable probe extensions, continuing without them: %v", err)
			return nil
		}
		return err
	}

	return nil
}

// Shutdown the receiver.
func (r *profilesReceiver) Shutdown(_ context.Context) error {
	var shutdownErr error
	for _, probe := range r.probes {
		if err := probe.Unload(); err != nil {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	r.probes = nil

	r.stopProfiler()

	if r.opts.onShutdown != nil {
		shutdownErr = errors.Join(shutdownErr, r.opts.onShutdown())
	}
	return shutdownErr
}

// startProfiler loads the eBPF tracer, starts the reporter and attaches the
// tracer to the kernel.
func (r *profilesReceiver) startProfiler(ctx context.Context) error {
	if err := linux.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}

	ctx, r.cancelFunc = context.WithCancel(ctx)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(ctx, r.cfg.ClockSyncInterval)

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(ctx, tracerConfig(r.cfg, r.opts, r.intervals, r.reporter))
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}
	r.tracer = trc
	log.Info("eBPF tracer loaded")

	// Wire probe snapshot sources into the reporter before starting its
	// collection loop.
	r.reporter.SetSnapshotSource(trc)

	if err := r.reporter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start reporter: %w", err)
	}

	now := time.Now()

	trc.StartPIDEventProcessor(ctx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(r.cfg.PinnedCPUIDs); err != nil {
		return fmt.Errorf("failed to attach to perf event: %w", err)
	}
	log.Info("Attached tracer program")

	if r.cfg.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
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

	if err := r.startTraceHandling(ctx, trc); err != nil {
		return fmt.Errorf("failed to start trace handling: %w", err)
	}

	return nil
}

// stopProfiler stops the reporter and the tracer. It is safe to call multiple
// times and from the trace handling goroutine.
func (r *profilesReceiver) stopProfiler() {
	r.shutdownOnceFn.Do(func() {
		log.Info("Stop processing ...")
		if r.cancelFunc != nil {
			r.cancelFunc()
		}
		if r.reporter != nil {
			r.reporter.Stop()
		}
		if r.tracer != nil {
			r.tracer.Close()
		}
	})
}

// tracerConfig translates the receiver configuration into a tracer configuration.
func tracerConfig(cfg *config.Config, opts *controllerOption, intervals *times.Times,
	rep reporter.Reporter,
) *tracer.Config {
	envVars := libpf.Set[string]{}
	for envVar := range strings.SplitSeq(cfg.IncludeEnvVars, ",") {
		envVar = strings.TrimSpace(envVar)
		if envVar != "" {
			envVars[envVar] = libpf.Void{}
		}
	}

	return &tracer.Config{
		TraceReporter:               rep,
		Intervals:                   intervals,
		InterpretersConfig:          cfg.Interpreters,
		FilterErrorFrames:           !cfg.SendErrorFrames,
		FilterIdleFrames:            !cfg.SendIdleFrames,
		FilterMinProcessAge:         cfg.FilterMinProcessAge,
		SamplesPerSecond:            cfg.SamplesPerSecond,
		MapScaleFactor:              int(cfg.MapScaleFactor),
		FrameCacheSize:              uint32(cfg.FrameCacheSize),
		KernelVersionCheck:          !cfg.NoKernelVersionCheck,
		VerboseMode:                 cfg.VerboseMode,
		BPFVerifierLogLevel:         uint32(cfg.BPFVerifierLogLevel),
		MaxConcurrentProgLoads:      int(cfg.MaxConcurrentProgLoads),
		ProbabilisticInterval:       cfg.ProbabilisticInterval,
		ProbabilisticThreshold:      cfg.ProbabilisticThreshold,
		IncludeEnvVars:              envVars,
		ExecutableReporter:          opts.executableReporter,
		BPFFSRoot:                   cfg.BPFFSRoot,
		OBIProcessCtx:               cfg.OBIProcessCtx,
		ProcessMetaEnrichers:        opts.processMetaEnrichers,
		PIDNamespaceTranslationMode: cfg.PIDNamespaceTranslationMode,
	}
}

// enableProbes resolves each configured extension ID from the host,
// verifies it implements ProbeExtension, and enables its probe on the tracer.
func (r *profilesReceiver) enableProbes(ctx context.Context, host component.Host) error {
	if len(r.cfg.Probes) == 0 {
		return nil
	}

	extensions := host.GetExtensions()
	for _, id := range r.cfg.Probes {
		ext, ok := extensions[id]
		if !ok {
			return fmt.Errorf("extension %q not found; ensure it is listed under service::extensions", id)
		}
		pe, ok := ext.(ProbeExtension)
		if !ok {
			return fmt.Errorf("extension %q does not implement ProbeExtension", id)
		}
		probe := pe.Probe()
		if err := r.tracer.Enable(ctx, probe); err != nil {
			return fmt.Errorf("enabling probe from extension %q: %w", id, err)
		}
		r.probes = append(r.probes, probe)
		log.Infof("Enabled probe from extension %q", id)
	}
	return nil
}

func (r *profilesReceiver) startTraceHandling(ctx context.Context, trc *tracer.Tracer) error {
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
				r.stopProfiler()
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}
