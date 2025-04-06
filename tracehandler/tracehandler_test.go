// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracehandler_test

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
)

type fakeTimes struct {
	monitorInterval time.Duration
}

func defaultTimes() *fakeTimes {
	return &fakeTimes{monitorInterval: 1 * time.Hour}
}

func (ft *fakeTimes) MonitorInterval() time.Duration { return ft.monitorInterval }

// fakeTraceProcessor implements a fake TraceProcessor used only within the test scope.
type fakeTraceProcessor struct{}

// Compile time check to make sure fakeTraceProcessor satisfies the interfaces.
var _ tracehandler.TraceProcessor = (*fakeTraceProcessor)(nil)

func (f *fakeTraceProcessor) ConvertTrace(trace *host.Trace) (*libpf.Trace, error) {
	var newTrace libpf.Trace
	newTrace.Hash = libpf.NewTraceHash(uint64(trace.Hash), uint64(trace.Hash))
	return &newTrace, nil
}

func (f *fakeTraceProcessor) ProcessedUntil(times.KTime) {}

func (f *fakeTraceProcessor) MaybeNotifyAPMAgent(*host.Trace, libpf.TraceHash, uint16) string {
	return ""
}

// arguments holds the inputs to test the appropriate functions.
type arguments struct {
	// trace holds the arguments for the function HandleTrace().
	trace *host.Trace
}

type mockReporter struct {
	t       *testing.T
	reports map[libpf.TraceHash]uint16
}

func (m *mockReporter) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	if _, exists := m.reports[trace.Hash]; exists {
		m.reports[trace.Hash]++
		return nil
	}
	m.reports[trace.Hash] = 1

	return nil
}

func TestTraceHandler(t *testing.T) {
	tests := map[string]struct {
		input          []arguments
		expireTimeout  time.Duration
		expectedEvents map[libpf.TraceHash]uint16
	}{
		// no input simulates a case where no data is provided as input
		// to the functions of traceHandler.
		"no input": {input: []arguments{}},

		// simulates a single trace being received.
		"single trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(0x1234)}},
		},
			expectedEvents: map[libpf.TraceHash]uint16{
				libpf.NewTraceHash(0x1234, 0x1234): 1,
			},
		},

		// double trace simulates a case where the same trace is encountered in quick succession.
		"double trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
		},
			expectedEvents: map[libpf.TraceHash]uint16{
				libpf.NewTraceHash(4, 4): 2,
			},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			r := &mockReporter{
				t:       t,
				reports: make(map[libpf.TraceHash]uint16),
			}

			traceChan := make(chan *host.Trace)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exitNotify, err := tracehandler.Start(ctx, r, &fakeTraceProcessor{},
				traceChan, defaultTimes(), 128)
			require.NoError(t, err)

			for _, input := range test.input {
				traceChan <- input.trace
			}

			cancel()
			<-exitNotify

			if !maps.Equal(r.reports, test.expectedEvents) {
				t.Fatalf("Expected %#v but got %#v", test.expectedEvents, r.reports)
			}
		})
	}
}
