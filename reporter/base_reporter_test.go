// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// createTestBaseReporter creates a minimal baseReporter for testing purposes
func createTestBaseReporter(t *testing.T, cfg *Config) *baseReporter {
	t.Helper()

	if cfg == nil {
		cfg = &Config{
			Name:             "test-agent",
			Version:          "v1.0.0",
			SamplesPerSecond: 100,
		}
	}

	pdataInstance, err := pdata.New(cfg.SamplesPerSecond, cfg.ExtraSampleAttrProd)
	require.NoError(t, err)

	return &baseReporter{
		cfg:                 cfg,
		name:                cfg.Name,
		version:             cfg.Version,
		pdata:               pdataInstance,
		traceEvents:         xsync.NewRWMutex(make(samples.TraceEventsTree)),
		collectionStartTime: time.Now(),
	}
}

// TestBaseReporterGenerate tests the Generate method and validates the output
func TestBaseReporterGenerate(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)

	trace1 := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x0102030400000000, 0x0000000000000000),
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 3)
			frames.Append(&libpf.Frame{
				Type:            libpf.KernelFrame,
				AddressOrLineno: 0x1000,
				FunctionName:    libpf.Intern("kernel_entry"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x2000,
				FunctionName:    libpf.Intern("native_handler"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x3000,
				FunctionName:    libpf.Intern("app_function"),
			})
			return frames
		}(),
	}

	trace2 := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x0506070800000000, 0x0000000000000000),
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 2)
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x4000,
				FunctionName:    libpf.Intern("another_function"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x5000,
				FunctionName:    libpf.Intern("leaf_function"),
			})
			return frames
		}(),
	}

	now := time.Now()
	meta1 := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.UnixNano()),
		Comm:           libpf.Intern("app1"),
		ProcessName:    libpf.Intern("app1"),
		ExecutablePath: libpf.Intern("/usr/bin/app1"),
		APMServiceName: "service1",
		ContainerID:    libpf.Intern("container-1"),
		PID:            1000,
		TID:            1001,
		CPU:            0,
		Origin:         support.TraceOriginSampling,
	}

	meta2 := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.Add(time.Second).UnixNano()),
		Comm:           libpf.Intern("app2"),
		ProcessName:    libpf.Intern("app2"),
		ExecutablePath: libpf.Intern("/usr/bin/app2"),
		APMServiceName: "service2",
		ContainerID:    libpf.Intern("container-2"),
		PID:            2000,
		TID:            2001,
		CPU:            1,
		Origin:         support.TraceOriginOffCPU,
		Value:          5000000, // 5ms
	}

	err := reporter.ReportTraceEvent(trace1, meta1)
	require.NoError(t, err)

	err = reporter.ReportTraceEvent(trace2, meta2)
	require.NoError(t, err)

	// Get the trace events tree for generation
	eventsTreePtr := reporter.traceEvents.RLock()
	eventsTree := *eventsTreePtr
	reporter.traceEvents.RUnlock(&eventsTreePtr)

	// Generate profiles
	collectionStart := reporter.collectionStartTime
	collectionEnd := time.Now()
	profiles, err := reporter.pdata.Generate(
		eventsTree,
		reporter.name,
		reporter.version,
		collectionStart,
		collectionEnd,
	)

	// Validate the generation succeeded
	require.NoError(t, err)
	require.NotNil(t, profiles)

	// Validate profile structure
	assert.Greater(t, profiles.SampleCount(), 0,
		"Should have at least one sample")
	assert.Equal(t, 2, profiles.ResourceProfiles().Len(),
		"Should have exactly two resource profile")

	// Check that we have scope profiles
	resourceProfile := profiles.ResourceProfiles().At(0)
	assert.Equal(t, 1, resourceProfile.ScopeProfiles().Len(), 0,
		"Should have exactly one scope profile")

	// Verify scope profile metadata
	scopeProfile := resourceProfile.ScopeProfiles().At(0)
	assert.Equal(t, reporter.name, scopeProfile.Scope().Name())
	assert.Equal(t, reporter.version, scopeProfile.Scope().Version())

	// Verify profiles exist
	assert.Greater(t, scopeProfile.Profiles().Len(), 0,
		"Should have at least one profile")
}
