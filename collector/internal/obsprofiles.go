// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
)

const (
	// receiverKey matches the attribute key used by receiverhelper.
	receiverKey = "receiver"
	// sampleTypeKey identifies the Profile.SampleType, formatted as
	// "type:unit", the samples belong to.
	sampleTypeKey = "sample_type"
)

// obsProfiles wraps a xconsumer.Profiles and reports receiver health metrics
// for every pprofile.Profile that is pushed into the pipeline.
//
// In contrast to receiverhelper.ObsReport, the metrics are recorded per
// pprofile.Profile with its sample type attached, as a single payload can hold
// multiple profiles with different sample types.
type obsProfiles struct {
	next     xconsumer.Profiles
	receiver attribute.KeyValue

	accepted metric.Int64Counter
	refused  metric.Int64Counter
	failed   metric.Int64Counter
}

var _ xconsumer.Profiles = (*obsProfiles)(nil)

func newObsProfiles(rs receiver.Settings, next xconsumer.Profiles) (*obsProfiles, error) {
	meter := rs.MeterProvider.Meter(metadata.ScopeName)

	accepted, err := meter.Int64Counter("otelcol_receiver_accepted_profile_samples",
		metric.WithDescription("Number of profile samples successfully pushed into the pipeline."),
		metric.WithUnit("{sample}"))
	if err != nil {
		return nil, err
	}
	refused, err := meter.Int64Counter("otelcol_receiver_refused_profile_samples",
		metric.WithDescription("Number of profile samples that could not be pushed into the pipeline."),
		metric.WithUnit("{sample}"))
	if err != nil {
		return nil, err
	}
	failed, err := meter.Int64Counter("otelcol_receiver_failed_profile_samples",
		metric.WithDescription("The number of profile samples that failed to be processed "+
			"by the receiver due to internal errors."),
		metric.WithUnit("{sample}"))
	if err != nil {
		return nil, err
	}

	return &obsProfiles{
		next:     next,
		receiver: attribute.String(receiverKey, rs.ID.String()),
		accepted: accepted,
		refused:  refused,
		failed:   failed,
	}, nil
}

func (o *obsProfiles) Capabilities() consumer.Capabilities {
	return o.next.Capabilities()
}

func (o *obsProfiles) ConsumeProfiles(ctx context.Context, pd pprofile.Profiles) error {
	// Collect the counts before calling ConsumeProfiles as the data may be
	// mutated downstream.
	counts := sampleCountsByType(pd)

	err := o.next.ConsumeProfiles(ctx, pd)

	// Follow receiverhelper: only distinguish downstream errors from internal
	// errors if the feature gate is enabled. Otherwise all errors are
	// considered "refused".
	counter := o.accepted
	if err != nil {
		if !receiverhelper.NewReceiverMetricsGate.IsEnabled() || consumererror.IsDownstream(err) {
			counter = o.refused
		} else {
			counter = o.failed
		}
	}

	for sampleType, count := range counts {
		counter.Add(ctx, count, metric.WithAttributes(o.receiver,
			attribute.String(sampleTypeKey, sampleType)))
	}
	return err
}

// sampleCountsByType returns the number of samples for each sample type
// of the profiles in pd.
func sampleCountsByType(pd pprofile.Profiles) map[string]int64 {
	strTable := pd.Dictionary().StringTable()
	counts := make(map[string]int64)

	rps := pd.ResourceProfiles()
	for i := 0; i < rps.Len(); i++ {
		sps := rps.At(i).ScopeProfiles()
		for j := 0; j < sps.Len(); j++ {
			ps := sps.At(j).Profiles()
			for k := 0; k < ps.Len(); k++ {
				p := ps.At(k)
				st := p.SampleType()
				sampleType := lookupString(strTable, st.TypeStrindex()) + ":" +
					lookupString(strTable, st.UnitStrindex())
				counts[sampleType] += int64(p.Samples().Len())
			}
		}
	}
	return counts
}

// lookupString returns the string at idx in strTable or an empty string if
// idx is out of range.
func lookupString(strTable pcommon.StringSlice, idx int32) string {
	if idx < 0 || int(idx) >= strTable.Len() {
		return ""
	}
	return strTable.At(int(idx))
}
