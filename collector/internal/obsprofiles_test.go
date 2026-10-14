// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"

	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
)

// sampleType describes a Profile.SampleType.
type sampleType struct {
	typ, unit string
}

// newTestProfiles returns profiles holding one profile per entry in
// sampleTypes, each with the given number of samples.
func newTestProfiles(sampleTypes []sampleType, samples []int) pprofile.Profiles {
	pd := pprofile.NewProfiles()
	strTable := pd.Dictionary().StringTable()
	strTable.Append("")

	ps := pd.ResourceProfiles().AppendEmpty().ScopeProfiles().AppendEmpty().Profiles()
	for i, st := range sampleTypes {
		p := ps.AppendEmpty()
		p.SampleType().SetTypeStrindex(int32(strTable.Len()))
		strTable.Append(st.typ)
		p.SampleType().SetUnitStrindex(int32(strTable.Len()))
		strTable.Append(st.unit)
		for range samples[i] {
			p.Samples().AppendEmpty()
		}
	}
	return pd
}

func TestObsProfiles(t *testing.T) {
	const (
		accepted = "otelcol_receiver_accepted_profile_samples"
		refused  = "otelcol_receiver_refused_profile_samples"
		failed   = "otelcol_receiver_failed_profile_samples"
	)
	downstreamErr := consumererror.NewDownstream(errors.New("downstream"))
	internalErr := errors.New("internal")

	tests := map[string]struct {
		gateEnabled bool
		consumerErr error
		metricName  string
	}{
		"accepted": {
			metricName: accepted,
		},
		"accepted with gate": {
			gateEnabled: true,
			metricName:  accepted,
		},
		"downstream error": {
			consumerErr: downstreamErr,
			metricName:  refused,
		},
		"downstream error with gate": {
			gateEnabled: true,
			consumerErr: downstreamErr,
			metricName:  refused,
		},
		"internal error": {
			consumerErr: internalErr,
			metricName:  refused,
		},
		"internal error with gate": {
			gateEnabled: true,
			consumerErr: internalErr,
			metricName:  failed,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gateID := receiverhelper.NewReceiverMetricsGate.ID()
			require.NoError(t, featuregate.GlobalRegistry().Set(gateID, tc.gateEnabled))
			t.Cleanup(func() {
				require.NoError(t, featuregate.GlobalRegistry().Set(gateID, false))
			})

			tel := componenttest.NewTelemetry()
			t.Cleanup(func() { require.NoError(t, tel.Shutdown(context.Background())) })

			rs := receivertest.NewNopSettings(metadata.Type)
			rs.TelemetrySettings = tel.NewTelemetrySettings()

			obs, err := newObsProfiles(rs, consumertest.NewErr(tc.consumerErr))
			require.NoError(t, err)

			pd := newTestProfiles([]sampleType{
				{"samples", "count"},
				{"off_cpu", "nanoseconds"},
				{"samples", "count"},
			}, []int{3, 2, 4})
			err = obs.ConsumeProfiles(context.Background(), pd)
			require.ErrorIs(t, err, tc.consumerErr)

			got, err := tel.GetMetric(tc.metricName)
			require.NoError(t, err)

			receiver := attribute.String(receiverKey, rs.ID.String())
			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        tc.metricName,
				Description: got.Description,
				Unit:        "{sample}",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Attributes: attribute.NewSet(receiver,
								attribute.String(sampleTypeKey, "samples:count")),
							Value: 7,
						},
						{
							Attributes: attribute.NewSet(receiver,
								attribute.String(sampleTypeKey, "off_cpu:nanoseconds")),
							Value: 2,
						},
					},
				},
			}, got, metricdatatest.IgnoreTimestamp())

			for _, other := range []string{accepted, refused, failed} {
				if other == tc.metricName {
					continue
				}
				_, err := tel.GetMetric(other)
				assert.Error(t, err, "unexpected metric %s", other)
			}
		})
	}
}

func TestSampleCountsByType(t *testing.T) {
	pd := newTestProfiles([]sampleType{
		{"samples", "count"},
		{"events", "count"},
		{"off_cpu", "nanoseconds"},
	}, []int{1, 0, 5})
	ps := pd.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles()
	// A profile with out of range sample type indices.
	p := ps.AppendEmpty()
	p.SampleType().SetTypeStrindex(42)
	p.SampleType().SetUnitStrindex(-1)
	p.Samples().AppendEmpty()
	// A profile with an out of range unit index only.
	p = ps.AppendEmpty()
	p.SampleType().SetTypeStrindex(1)
	p.SampleType().SetUnitStrindex(42)
	p.Samples().AppendEmpty()

	assert.Equal(t, map[string]int64{
		"samples:count":       1,
		"events:count":        0,
		"off_cpu:nanoseconds": 5,
		":":                   1,
		"samples:":            1,
	}, sampleCountsByType(pd))
}
