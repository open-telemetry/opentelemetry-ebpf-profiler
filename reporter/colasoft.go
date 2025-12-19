package reporter

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"github.com/toliu/opentelemetry-ebpf-profiler/support"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"maps"
	"sync"
	"time"
)

type (
	ColaSoftConsumerFunc func(ctx context.Context, tds map[uint32]pprofile.Profiles) error
	ColaSoft             struct {
		*CollectorReporter
		sr                              SymbolReporter
		ctx                             context.Context
		consumer                        ColaSoftConsumerFunc
		cacheMapping                    map[uint32]map[libpf.Origin]samples.KeyToEventMapping
		cacheEventSCount                int
		lastReportTime                  time.Time
		cacheEventSTolerance            int
		cacheEventSTimeout              time.Duration
		consumerLock                    sync.Mutex
		hotspotLock                     sync.Mutex
		hotspotMemProfileChan           chan map[uint32]pprofile.Profiles
		hotspotMemProfileCancels        map[int]context.CancelFunc
		hotspotMemProfileReporterCancel context.CancelFunc
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
		cacheMapping:             make(map[uint32]map[libpf.Origin]samples.KeyToEventMapping),
		cacheEventSCount:         0,
		cacheEventSTolerance:     cacheEventSTolerance,
		cacheEventSTimeout:       cacheEventSTimeout,
		hotspotMemProfileChan:    make(chan map[uint32]pprofile.Profiles, 100),
		hotspotMemProfileCancels: make(map[int]context.CancelFunc)}, nil
}

func (c *ColaSoft) Start(parent context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(parent)
	c.ctx = ctx

	c.runLoop.Start(ctx, c.cfg.ReportInterval, func() {
		if err := c.reportProfile(context.Background()); err != nil {
			log.Errorf("Request failed: %v", err)
		}
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		c.pdata.Purge()
		c.cgroupv2ID.PurgeExpired()
	})

	// handle memprofile trace
	c.memRunLoop.Start(ctx, 10*time.Second, func() {
		if err := c.reportMemProfile(context.Background()); err != nil {
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
		<-c.memRunLoop.stopSignal
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
				events[pid][kind][key] = value
			} else {
				if _traceEvents, ok := events[pid][kind][key]; ok {
					_traceEvents.Timestamps = append(_traceEvents.Timestamps, value.Timestamps...)
					_traceEvents.OffTimes = append(_traceEvents.OffTimes, value.OffTimes...)
					_traceEvents.MemAlloc = append(_traceEvents.MemAlloc, value.MemAlloc...)
				} else {
					events[pid][kind][key] = value
				}
			}
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
	c.consumerLock.Lock()
	err := c.consumer(ctx, tds)
	c.consumerLock.Unlock()
	c.cacheMapping = make(map[uint32]map[libpf.Origin]samples.KeyToEventMapping)
	c.cacheEventSCount = 0
	c.lastReportTime = time.Now()
	return err
}

// 单独处理memProfile的数据，间隔一定时间上报
func (c *ColaSoft) reportMemProfile(ctx context.Context) error {
	var removeEvts []samples.TraceAndMetaKey
	defer func() {
		traceEvents := c.memTraceEvents.WLock()
		headEvts := (*traceEvents)[support.TraceOriginHeap]
		for _, key := range removeEvts {
			delete(headEvts, key)
		}
		c.memTraceEvents.WUnlock(&traceEvents)
	}()
	traceEvents := c.memTraceEvents.WLock()
	var mappings = make(map[libpf.Origin]samples.KeyToEventMapping)
	mappings[support.TraceOriginHeap] = maps.Clone((*traceEvents)[support.TraceOriginHeap])
	c.memTraceEvents.WUnlock(&traceEvents)
	events := make(map[uint32]map[libpf.Origin]samples.KeyToEventMapping)
	for kind, mapping := range mappings {
		for key, value := range mapping {
			pid := uint32(key.Pid)
			if _, ok := c.targetPids.Load(libpf.PID(pid)); !ok {
				removeEvts = append(removeEvts, key)
				continue
			}
			if _, ok := events[pid]; !ok {
				events[pid] = make(map[libpf.Origin]samples.KeyToEventMapping)
			}
			if _, ok := events[pid][kind]; !ok {
				events[pid][kind] = make(samples.KeyToEventMapping)
			}
			events[pid][kind][key] = value
		}
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
	c.consumerLock.Lock()
	defer c.consumerLock.Unlock()
	return c.consumer(ctx, tds)
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

func (c *ColaSoft) ReportHotspotMemProfile() {
	ctx, cancel := context.WithCancel(c.ctx)
	c.hotspotMemProfileReporterCancel = cancel
	go func() {
		ticker := time.NewTicker(time.Second)
		for {
			select {
			case <-ticker.C:
				var tds map[uint32]pprofile.Profiles
				size := len(c.hotspotMemProfileChan)
				for i := 0; i < size; i++ {
					d := <-c.hotspotMemProfileChan
					if tds == nil {
						tds = d
					} else {
						maps.Insert(tds, maps.All(d))
					}
				}
				if len(tds) > 0 {
					c.completeHotspotMemProfileData(tds)
					c.consumerLock.Lock()
					err := c.consumer(context.Background(), tds)
					if err != nil {
						log.Errorf("consume hotspot memprofile data failed, %s", err)
					}
					c.consumerLock.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *ColaSoft) StopHotspotMemProfiling(pid int) {
	c.hotspotLock.Lock()
	defer c.hotspotLock.Unlock()
	if cancel, ok := c.hotspotMemProfileCancels[pid]; ok {
		cancel()
	}
	delete(c.hotspotMemProfileCancels, pid)
	if len(c.hotspotMemProfileCancels) == 0 && c.hotspotMemProfileReporterCancel != nil {
		c.hotspotMemProfileReporterCancel()
		c.hotspotMemProfileReporterCancel = nil
	}
}

func (c *ColaSoft) StartHotspotMemProfiling(cfg *hotspotmem.OTLPProfilerConfig) error {
	c.hotspotLock.Lock()
	defer c.hotspotLock.Unlock()
	if _, ok := c.hotspotMemProfileCancels[cfg.PID]; ok {
		return nil
	}
	ctx, cancel := context.WithCancel(c.ctx)
	err := hotspotmem.StartMemAllocProfilingOTLP(ctx, cfg, c.hotspotMemProfileChan)
	if err != nil {
		log.Infof("Failed to start profiling: %v", err)
		cancel()
		return err
	}
	c.hotspotMemProfileCancels[cfg.PID] = cancel
	if c.hotspotMemProfileReporterCancel == nil {
		c.ReportHotspotMemProfile()
	}
	return nil
}

func (c *ColaSoft) completeHotspotMemProfileData(tds map[uint32]pprofile.Profiles) {
	for pid, td := range tds {
		td.ResourceProfiles().RemoveIf(func(profiles pprofile.ResourceProfiles) bool {
			profiles.Resource().Attributes().PutBool("hotspotMem", true)
			profiles.ScopeProfiles().RemoveIf(func(scopeProfiles pprofile.ScopeProfiles) bool {
				scopeProfiles.Profiles().RemoveIf(func(profile pprofile.Profile) bool {
					attrMgr := samples.NewAttrTableManager(profile.AttributeTable())
					if profile.Sample().Len() == 0 {
						return false
					}
					for i := 0; i < profile.LocationTable().Len(); i++ {
						loc := profile.LocationTable().At(i)
						attrMgr.AppendOptionalString(loc.AttributeIndices(),
							"profile.frame.type", "jvm")
					}
					profile.Sample().RemoveIf(func(sample pprofile.Sample) bool {
						containerID, _ := libpf.LookupCgroupv2(c.cgroupv2ID, libpf.PID(pid))
						attrMgr.AppendOptionalString(sample.AttributeIndices(),
							semconv.ContainerIDKey, containerID)
						attrMgr.AppendOptionalString(sample.AttributeIndices(),
							semconv.ThreadNameKey, "java")
						//attrMgr.AppendOptionalString(sample.AttributeIndices(),
						//	semconv.ProcessExecutableNameKey, traceKey.ProcessName)
						//attrMgr.AppendOptionalString(sample.AttributeIndices(),
						//	semconv.ProcessExecutablePathKey, traceKey.ExecutablePath)
						attrMgr.AppendInt(sample.AttributeIndices(),
							semconv.ProcessPIDKey, int64(pid))
						if c.pdata.ExtraSampleAttrProd != nil {
							extraMeta := uint64(pid)<<32 | uint64(0) // 这个逻辑来自cloudcapture
							extra := c.pdata.ExtraSampleAttrProd.ExtraSampleAttrs(attrMgr, extraMeta)
							sample.AttributeIndices().Append(extra...)
						}
						return false
					})
					return false
				})
				return false
			})
			return false
		})
	}
}

func (c *ColaSoft) SyncHotspotMemProfilingCfg(cfg *hotspotmem.OTLPProfilerConfig) {
	// 需要重启java的profiler
	c.hotspotLock.Lock()
	var pids []int
	for pid, cancel := range c.hotspotMemProfileCancels {
		cancel()
		pids = append(pids, pid)
	}
	c.hotspotMemProfileCancels = make(map[int]context.CancelFunc)
	c.hotspotLock.Unlock()
	for _, pid := range pids {
		_cfg := &hotspotmem.OTLPProfilerConfig{
			PID:           pid,
			AllocInterval: cfg.AllocInterval,
			DumpInterval:  cfg.DumpInterval,
		}
		if err := c.StartHotspotMemProfiling(_cfg); err != nil {
			log.Errorf("Failed to start hotspotMemProfiling for pid %d: %v", pid, err)
		}
	}
}
