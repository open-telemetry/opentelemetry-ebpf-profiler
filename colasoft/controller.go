package colasoft

import (
	"context"
	"time"

	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"

	"github.com/toliu/opentelemetry-ebpf-profiler/internal/controller"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/tracer"
)

type (
	Collector struct {
		sr SymbolReporter

		ctrl     *controller.Controller
		reporter *reporter.ColaSoft
		cfg      *controller.Config
	}

	StartCfg struct {
		Freq, OffCpuThreshold, CacheEventSTolerance int
		Interval, CacheEventSTimeout                time.Duration
		TargetPids, MemTargetPIDs                   map[libpf.PID]bool
		MemProfileBlock                             uint64
	}
)

func NewCollector(sr SymbolReporter) *Collector { return &Collector{sr: sr} }

func (c *Collector) Start(ctx context.Context, cfg StartCfg) error {
	if c.cfg != nil {
		if c.cfg.ReporterInterval == cfg.Interval &&
			c.cfg.SamplesPerSecond == cfg.Freq &&
			c.cfg.OffCPUThreshold == uint(cfg.OffCpuThreshold) &&
			c.cfg.MemProfileBlock == cfg.MemProfileBlock {
			return nil
		}
		c.Stop()
	}

	rpt, err := reporter.NewColaSoft(cfg.Freq, cfg.Interval, c.sr, c.sr.ConsumeProfilesFunc,
		noFrameOpSymbolReporter{c.sr}, cfg.CacheEventSTolerance, cfg.CacheEventSTimeout)
	if err != nil {
		return err
	}

	controllerCfg := &controller.Config{
		MonitorInterval: time.Second * 5, ClockSyncInterval: time.Minute * 3,
		NoKernelVersionCheck: true, ProbabilisticInterval: time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax * 2,
		ReporterInterval:       cfg.Interval, SamplesPerSecond: cfg.Freq, Reporter: rpt,
		Tracers:         "perl,php,python,hotspot,ruby,v8",
		OffCPUThreshold: uint(cfg.OffCpuThreshold),
		TargetPIDs:      libpf.NewMutablePIDFilter(cfg.TargetPids),
		MemTargetPIDs:   libpf.NewMutablePIDFilter(cfg.MemTargetPIDs),
		MemProfileBlock: cfg.MemProfileBlock,
	}
	ctrl := controller.New(controllerCfg)
	if err = ctrl.Start(ctx); err != nil {
		return err
	}
	c.ctrl = ctrl
	c.reporter = rpt
	c.cfg = controllerCfg
	return nil
}

func (c *Collector) Stop() {
	if c.ctrl != nil {
		c.ctrl.Shutdown()
		c.ctrl = nil
		c.reporter = nil
		c.cfg = nil
	}
}

func (c *Collector) SyncMemProfileBlock(memProfileBlock uint64) error {
	return c.ctrl.SyncMemProfileBlock(memProfileBlock)
}
