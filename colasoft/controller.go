package colasoft

import (
	"context"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"time"

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
)

func NewCollector(sr SymbolReporter) *Collector { return &Collector{sr: sr} }

func (c *Collector) Start(ctx context.Context, freq, offCpuThreshold int, interval time.Duration, targetPIDs []libpf.PID, cacheEventSTolerance int, cacheEventSTimeout time.Duration) error {
	if c.cfg != nil {
		if c.cfg.ReporterInterval == interval &&
			c.cfg.SamplesPerSecond == freq &&
			c.cfg.OffCPUThreshold == uint(offCpuThreshold) {
			return nil
		}
		c.Stop()
	}

	rpt, err := reporter.NewColaSoft(freq, interval, c.sr, c.sr.ConsumeProfilesFunc, noFrameOpSymbolReporter{c.sr}, cacheEventSTolerance, cacheEventSTimeout)
	if err != nil {
		return err
	}

	cfg := &controller.Config{
		MonitorInterval: time.Second * 5, ClockSyncInterval: time.Minute * 3,
		NoKernelVersionCheck: true, ProbabilisticInterval: time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax * 2,
		ReporterInterval:       interval, SamplesPerSecond: freq, Reporter: rpt,
		Tracers:         "perl,php,python,hotspot,ruby,v8",
		OffCPUThreshold: uint(offCpuThreshold),
		TargetPIDs:      targetPIDs,
	}
	ctrl := controller.New(cfg)
	if err = ctrl.Start(ctx); err != nil {
		return err
	}
	c.ctrl = ctrl
	c.reporter = rpt
	c.cfg = cfg
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

func (c *Collector) SyncTargetPIDs(targetPIds []libpf.PID) error {
	return c.ctrl.SyncTargetPIDs(targetPIds)
}
