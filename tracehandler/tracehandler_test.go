// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracehandler_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
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

func (f *fakeTraceProcessor) SymbolizationComplete(times.KTime) {}

func (f *fakeTraceProcessor) MaybeNotifyAPMAgent(*host.Trace, libpf.TraceHash, uint16) string {
	return ""
}

// arguments holds the inputs to test the appropriate functions.
type arguments struct {
	// trace holds the arguments for the function HandleTrace().
	trace *host.Trace
}

// reportedCount / reportedTrace hold the information reported from traceHandler
// via the reporter functions (reportCountForTrace / reportFramesForTrace).
type reportedCount struct {
	traceHash libpf.TraceHash
	count     uint16
}

type reportedTrace struct {
	traceHash libpf.TraceHash
}

type mockReporter struct {
	t              *testing.T
	reportedCounts []reportedCount
	reportedTraces []reportedTrace
}

func (m *mockReporter) ReportFramesForTrace(trace *libpf.Trace) {
	m.reportedTraces = append(m.reportedTraces, reportedTrace{traceHash: trace.Hash})
	m.t.Logf("reportFramesForTrace: new trace 0x%x", trace.Hash)
}

func (m *mockReporter) ReportCountForTrace(traceHash libpf.TraceHash,
	count uint16, _ *reporter.TraceEventMeta) {
	m.reportedCounts = append(m.reportedCounts, reportedCount{
		traceHash: traceHash,
		count:     count,
	})
	m.t.Logf("reportCountForTrace: 0x%x count: %d", traceHash, count)
}

func (m *mockReporter) SupportsReportTraceEvent() bool { return false }

func (m *mockReporter) ReportTraceEvent(_ *libpf.Trace, _ *reporter.TraceEventMeta) {
}

func TestTraceHandler(t *testing.T) {
	tests := map[string]struct {
		input          []arguments
		expectedCounts []reportedCount
		expectedTraces []reportedTrace
		expireTimeout  time.Duration
	}{
		// no input simulates a case where no data is provided as input
		// to the functions of traceHandler.
		"no input": {input: []arguments{}},

		// simulates a single trace being received.
		"single trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(0x1234)}},
		},
			expectedTraces: []reportedTrace{{traceHash: libpf.NewTraceHash(0x1234, 0x1234)}},
			expectedCounts: []reportedCount{
				{traceHash: libpf.NewTraceHash(0x1234, 0x1234), count: 1},
			},
		},

		// double trace simulates a case where the same trace is encountered in quick succession.
		"double trace": {input: []arguments{
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
			{trace: &host.Trace{Hash: host.TraceHash(4)}},
		},
			expectedTraces: []reportedTrace{{traceHash: libpf.NewTraceHash(4, 4)}},
			expectedCounts: []reportedCount{
				{traceHash: libpf.NewTraceHash(4, 4), count: 1},
				{traceHash: libpf.NewTraceHash(4, 4), count: 1},
			},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			r := &mockReporter{t: t}

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

			assert.Equal(t, len(test.expectedCounts), len(r.reportedCounts))
			assert.Equal(t, len(test.expectedTraces), len(r.reportedTraces))

			// Expected and reported traces order should match.
			assert.Equal(t, test.expectedTraces, r.reportedTraces)

			for _, expCount := range test.expectedCounts {
				// Expected and reported count order doesn't necessarily match.
				found := false
				for _, repCount := range r.reportedCounts {
					if expCount == repCount {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected count %d for trace 0x%x not found",
					expCount.count, expCount.traceHash)
			}
		})
	}
}
