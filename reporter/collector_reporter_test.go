package reporter

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestCollectorReporterReportTraceEvent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		trace  *libpf.Trace
		meta   *TraceEventMeta
		nextFn consumerprofiles.ConsumeProfilesFunc
	}{
		{
			name:  "with no next consumer",
			trace: &libpf.Trace{},
			meta:  &TraceEventMeta{},
		},
		{
			name:  "with a next consumer that succeeds",
			trace: &libpf.Trace{},
			meta:  &TraceEventMeta{},
			nextFn: func(_ context.Context, _ pprofile.Profiles) error {
				return nil
			},
		},
		{
			name:  "with a next consumer that returns an error",
			trace: &libpf.Trace{},
			meta:  &TraceEventMeta{},
			nextFn: func(_ context.Context, _ pprofile.Profiles) error {
				return errors.New("next consumer failed")
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var next consumerprofiles.Profiles

			if tt.nextFn != nil {
				var err error
				next, err = consumerprofiles.NewProfiles(tt.nextFn)
				require.NoError(t, err)
			}

			r, err := NewCollector(&Config{
				ExecutablesCacheElements: 1,
				FramesCacheElements:      1,
				CGroupCacheElements:      1,
			}, next)
			require.NoError(t, err)
			r.ReportTraceEvent(tt.trace, tt.meta)
		})
	}
}
