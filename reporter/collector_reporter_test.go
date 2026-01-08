package reporter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestCollectorReporterReportTraceEvent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		trace  *libpf.Trace
		meta   *samples.TraceEventMeta
		nextFn xconsumer.ConsumeProfilesFunc
	}{
		{
			name:  "with no next consumer",
			trace: &libpf.Trace{},
			meta:  &samples.TraceEventMeta{},
		},
		{
			name:  "with a next consumer that succeeds",
			trace: &libpf.Trace{},
			meta:  &samples.TraceEventMeta{},
			nextFn: func(_ context.Context, _ pprofile.Profiles) error {
				return nil
			},
		},
		{
			name:  "with a next consumer that returns an error",
			trace: &libpf.Trace{},
			meta:  &samples.TraceEventMeta{},
			nextFn: func(_ context.Context, _ pprofile.Profiles) error {
				return errors.New("next consumer failed")
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var next xconsumer.Profiles

			if tt.nextFn != nil {
				var err error
				next, err = xconsumer.NewProfiles(tt.nextFn)
				require.NoError(t, err)
			}

			r, err := NewCollector(&Config{}, next)
			require.NoError(t, err)
			if err := r.ReportTraceEvent(tt.trace, tt.meta); err != nil &&
				!errors.Is(err, errUnknownOrigin) {
				t.Fatal(err)
			}
		})
	}
}

func TestCollectorReporterShutdown(t *testing.T) {
	var cancelled atomic.Bool
	consumerStarted := make(chan struct{})
	next, err := xconsumer.NewProfiles(func(ctx context.Context, _ pprofile.Profiles) error {
		close(consumerStarted)
		select {
		case <-ctx.Done():
			cancelled.Store(true)
			return nil
		}
	})
	require.NoError(t, err)

	r, err := NewCollector(&Config{
		ReportInterval: 10 * time.Millisecond,
	}, next)
	require.NoError(t, err)

	traceEventsPtr := r.traceEvents.WLock()
	tree := (*traceEventsPtr)
	tree[libpf.NullString] = map[libpf.Origin]samples.KeyToEventMapping{
		support.TraceOriginProbe: map[samples.TraceAndMetaKey]*samples.TraceEvents{
			{Pid: 1}: {
				Frames: func() libpf.Frames {
					frames := make(libpf.Frames, 0, 1)
					frames.Append(&libpf.Frame{
						Type:            libpf.KernelFrame,
						AddressOrLineno: 0xef,
						FunctionName:    libpf.Intern("func1"),
					})
					return frames
				}(),
				Timestamps: []uint64{1, 2, 3, 4},
			},
		},
	}
	r.traceEvents.WUnlock(&traceEventsPtr)

	ctx, cancelFn := context.WithCancel(t.Context())
	require.NoError(t, r.Start(ctx))
	// BLOCK until the consumer is actually running
	<-consumerStarted
	cancelFn()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.True(collect, cancelled.Load())
	}, 5*time.Second, 100*time.Millisecond, "consumer did not exit after context cancellation")
}
