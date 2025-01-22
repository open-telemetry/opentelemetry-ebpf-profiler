// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"maps"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/consumer/xconsumer"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// CollectorReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	*baseReporter

	nextConsumer xconsumer.Profiles
}

// NewCollector builds a new CollectorReporter
func NewCollector(cfg *Config, nextConsumer xconsumer.Profiles) (*CollectorReporter, error) {
	cgroupv2ID, err := lru.NewSynced[libpf.PID, string](cfg.CGroupCacheElements,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	if err != nil {
		return nil, err
	}
	// Set a lifetime to reduce the risk of invalid data in case of PID reuse.
	cgroupv2ID.SetLifetime(90 * time.Second)

	// Next step: Dynamically configure the size of this LRU.
	// Currently, we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	data, err := pdata.New(
		cfg.SamplesPerSecond,
		cfg.ExecutablesCacheElements,
		cfg.FramesCacheElements,
		cfg.ExtraSampleAttrProd,
	)
	if err != nil {
		return nil, err
	}

	originsMap := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		originsMap[origin] = make(samples.KeyToEventMapping)
	}

	return &CollectorReporter{
		baseReporter: &baseReporter{
			cfg:          cfg,
			name:         cfg.Name,
			version:      cfg.Version,
			pdata:        data,
			cgroupv2ID:   cgroupv2ID,
			traceEvents:  xsync.NewRWMutex(originsMap),
			hostmetadata: hostmetadata,
			runLoop: &runLoop{
				stopSignal: make(chan libpf.Void),
			},
		},
		nextConsumer: nextConsumer,
	}, nil
}

func (r *CollectorReporter) Start(ctx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(ctx)

	r.runLoop.Start(ctx, r.cfg.ReportInterval, func() {
		if err := r.reportProfile(context.Background()); err != nil {
			log.Errorf("Request failed: %v", err)
		}
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		r.pdata.Purge()
		r.cgroupv2ID.PurgeExpired()
	})

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-r.runLoop.stopSignal
		cancelReporting()
	}()

	return nil
}

func (r *CollectorReporter) GetMetrics() Metrics {
	return Metrics{}
}

// reportProfile creates and sends out a profile.
func (r *CollectorReporter) reportProfile(ctx context.Context) error {
	traceEvents := r.traceEvents.WLock()
	events := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		events[origin] = maps.Clone((*traceEvents)[origin])
		clear((*traceEvents)[origin])
	}
	r.traceEvents.WUnlock(&traceEvents)

	profiles := r.pdata.Generate(events)
	if profiles.SampleCount() == 0 {
		log.Debugf("Skip sending profile with no samples")
		return nil
	}

	return r.nextConsumer.ConsumeProfiles(ctx, profiles)
}
