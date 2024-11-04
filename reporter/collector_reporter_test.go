package reporter

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

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
				CacheSize: 1,
			}, next)
			require.NoError(t, err)
			r.ReportTraceEvent(tt.trace, tt.meta)
		})
	}
}

func TestCollectoReportProfile(t *testing.T) {
	for _, tt := range []struct {
		name              string
		reportTraceEvents func(*testing.T, Reporter)

		wantConsumedCount int
		buildWantProfiles func(*testing.T) pprofile.Profiles
		wantErr           error
	}{
		{
			name:              "with no data sent yet",
			wantConsumedCount: 0,
		},
		{
			name: "with a single sample",
			reportTraceEvents: func(_ *testing.T, r Reporter) {
				r.ReportTraceEvent(
					&libpf.Trace{},
					&TraceEventMeta{
						Timestamp:      libpf.UnixTime64(1),
						Comm:           "comm",
						APMServiceName: "opentelemetry-ebpf-profiler",
					},
				)
			},

			wantConsumedCount: 1,
			buildWantProfiles: func(t *testing.T) pprofile.Profiles {
				prof := pprofile.NewProfiles()

				rp := prof.ResourceProfiles().AppendEmpty()
				sp := rp.ScopeProfiles().AppendEmpty()

				pc := sp.Profiles().AppendEmpty()
				pc.SetProfileID(pprofile.ProfileID([]byte("profile-id-for-tests")))
				pc.SetStartTime(1)
				pc.SetEndTime(1)

				profile := pc.Profile()
				profile.SetStartTime(1)

				fn := profile.Function().AppendEmpty()
				fn.SetName(0)
				fn.SetFilename(0)

				profile.StringTable().FromRaw([]string{
					"",
					"samples",
					"count",
					"cpu",
					"nanoseconds",
					"AAAAAAAAAAAAAAAAAAAAAA",
				})

				require.NoError(t, profile.AttributeTable().FromRaw(map[string]any{
					string(semconv.ThreadNameKey):  "comm",
					string(semconv.ServiceNameKey): "opentelemetry-ebpf-profiler",
				}))

				st := profile.SampleType().AppendEmpty()
				st.SetType(1)
				st.SetUnit(2)

				pt := profile.PeriodType()
				pt.SetType(3)
				pt.SetUnit(4)
				profile.SetPeriod(1000000000)

				sample := profile.Sample().AppendEmpty()
				sample.SetStacktraceIdIndex(5)
				sample.Value().FromRaw([]int64{1})
				sample.TimestampsUnixNano().FromRaw([]uint64{1})
				sample.Attributes().FromRaw([]uint64{0, 1})

				return prof
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var consumedCount int
			var gotProfiles pprofile.Profiles
			next, err := consumerprofiles.NewProfiles(
				func(_ context.Context, p pprofile.Profiles) error {
					consumedCount++
					gotProfiles = p
					return nil
				},
			)
			require.NoError(t, err)

			r, err := NewCollector(&Config{
				CacheSize:        1,
				SamplesPerSecond: 1,
			}, next)
			require.NoError(t, err)

			if tt.reportTraceEvents != nil {
				tt.reportTraceEvents(t, r)
			}

			err = r.reportProfile(context.Background())
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, tt.wantErr, err)
			}

			assert.Equal(t, tt.wantConsumedCount, consumedCount)

			// If we don't expect anything to have been consumed, we don't have
			// anything else to check.
			if tt.wantConsumedCount == 0 {
				return
			}

			wantProfiles := tt.buildWantProfiles(t)
			if gotProfiles.SampleCount() == 0 {
				assert.Equal(t, wantProfiles.SampleCount(), gotProfiles.SampleCount())
				return
			}

			// Set a dummy profile ID to allow reproducible assertions
			assert.NotEmpty(t, gotProfiles.ResourceProfiles().At(0).
				ScopeProfiles().At(0).
				Profiles().At(0).ProfileID())
			gotProfiles.ResourceProfiles().At(0).
				ScopeProfiles().At(0).
				Profiles().At(0).
				SetProfileID(pprofile.ProfileID([]byte("profile-id-for-tests")))

			assert.Empty(t, cmp.Diff(
				wantProfiles,
				gotProfiles,
				cmp.Comparer(func(a pprofile.Profiles, b pprofile.Profiles) bool {
					return assert.ObjectsAreEqualValues(a, b)
				}),
			))
		})
	}
}
