package reporter

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"github.com/toliu/opentelemetry-ebpf-profiler/support"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"maps"
	"time"
)

type (
	ColaSoftConsumerFunc func(ctx context.Context, tds map[uint32]pprofile.Profiles) error
	ColaSoft             struct {
		*CollectorReporter
		sr SymbolReporter

		consumer             ColaSoftConsumerFunc
		cacheMapping         map[uint32]map[libpf.Origin]samples.KeyToEventMapping
		cacheEventSCount     int
		lastReportTime       time.Time
		cacheEventSTolerance int
		cacheEventSTimeout   time.Duration
	}
)

var _ Reporter = (*ColaSoft)(nil)

func NewColaSoft(
	freq int, interval time.Duration,
	extra samples.SampleAttrProducer,
	f ColaSoftConsumerFunc,
	sr SymbolReporter,
	cacheEventSTolerance int,
	cacheEventSTimeout time.Duration,
) (*ColaSoft, error) {
	cfg := &Config{
		ExecutablesCacheElements: 16384,
		FramesCacheElements:      65536,
		CGroupCacheElements:      1024,
		SamplesPerSecond:         freq,
		ReportInterval:           interval,
		ExtraSampleAttrProd:      extra,
	}

	r, err := NewCollector(cfg, nil)
	if err != nil {
		return nil, err
	}

	return &ColaSoft{CollectorReporter: r, sr: sr, consumer: f,
		cacheMapping:         make(map[uint32]map[libpf.Origin]samples.KeyToEventMapping),
		cacheEventSCount:     0,
		cacheEventSTolerance: cacheEventSTolerance,
		cacheEventSTimeout:   cacheEventSTimeout}, nil
}

func (c *ColaSoft) Start(parent context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(parent)

	c.runLoop.Start(ctx, c.cfg.ReportInterval, func() {
		if err := c.reportProfile(context.Background()); err != nil {
			log.Errorf("Request failed: %v", err)
		}
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		c.pdata.Purge()
		c.cgroupv2ID.PurgeExpired()
	})

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-c.runLoop.stopSignal
		cancelReporting()
	}()

	return nil
}

func (c *ColaSoft) reportProfile(ctx context.Context) error {
	traceEvents := c.traceEvents.WLock()
	var mappings = make(map[libpf.Origin]samples.KeyToEventMapping)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling, support.TraceOriginOffCPU} {
		mappings[origin] = maps.Clone((*traceEvents)[origin])
		clear((*traceEvents)[origin])
	}
	c.traceEvents.WUnlock(&traceEvents)
	events := c.cacheMapping
	for kind, mapping := range mappings {
		c.cacheEventSCount += len(mapping)
		for key, value := range mapping {
			pid := uint32(key.Pid)
			if _, ok := events[pid]; !ok {
				events[pid] = make(map[libpf.Origin]samples.KeyToEventMapping)
			}
			if _, ok := events[pid][kind]; !ok {
				events[pid][kind] = make(samples.KeyToEventMapping)
			}
			events[pid][kind][key] = value
		}
	}
	// 这里至少1分钟上报一次
	if c.cacheEventSCount < c.cacheEventSTolerance && time.Since(c.lastReportTime) < c.cacheEventSTimeout {
		return nil
	}
	tds := make(map[uint32]pprofile.Profiles)
	for pid, val := range events {
		td := c.pdata.Generate(val)
		if td.SampleCount() == 0 {
			log.Tracef("Skip sending profile with no samples for pid %d", pid)
			continue
		}
		tds[pid] = td
	}
	if len(tds) == 0 {
		return nil
	}

	err := c.consumer(ctx, tds)
	c.cacheMapping = make(map[uint32]map[libpf.Origin]samples.KeyToEventMapping)
	c.cacheEventSCount = 0
	c.lastReportTime = time.Now()
	return err
}

func (c *ColaSoft) ExecutableKnown(fileID libpf.FileID) bool {
	return c.CollectorReporter.ExecutableKnown(fileID) || c.sr.ExecutableKnown(fileID)
}

func (c *ColaSoft) ExecutableMetadata(args *ExecutableMetadataArgs) {
	if args.Interp == libpf.Native {
		c.sr.ExecutableMetadata(args)
	}
	c.CollectorReporter.ExecutableMetadata(args)
}
