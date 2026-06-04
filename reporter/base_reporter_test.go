// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

var (
	profileTypeSampling = &samples.TypeMetadata{
		PeriodType: "cpu",
		PeriodUnit: "nanoseconds",
		SampleType: "samples",
		SampleUnit: "count",
	}
	profileTypeOffCPU = &samples.TypeMetadata{
		SampleType:   "off_cpu",
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
	profileTypeProbe = &samples.TypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	}
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
		ExecutablePath: libpf.Intern("/usr/bin/app1"),
		APMServiceName: "service1",
		ContainerID:    libpf.Intern("container-1"),
		PID:            1000,
		TID:            1001,
		CPU:            0,
		ProfileType:    profileTypeSampling,
	}

	meta2 := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.Add(time.Second).UnixNano()),
		Comm:           libpf.Intern("app2"),
		ExecutablePath: libpf.Intern("/usr/bin/app2"),
		APMServiceName: "service2",
		ContainerID:    libpf.Intern("container-2"),
		PID:            2000,
		TID:            2001,
		CPU:            1,
		ProfileType:    profileTypeOffCPU,
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

// processNameAttrProducer is a test SampleAttrProducer that reads "process.name" from
// TraceEventMeta.ExtraMeta (populated by a ProcessMetaEnricher) and emits it as a
// sample attribute, exercising the full enricher → TraceEventMeta → attribute pipeline.
type processNameAttrProducer struct{}

func (p *processNameAttrProducer) CollectExtraSampleMeta(_ *libpf.Trace, meta *samples.TraceEventMeta) any {
	if meta.ExtraMeta == nil {
		return ""
	}
	return meta.ExtraMeta["process.name"]
}

func (p *processNameAttrProducer) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, extraMeta any) []int32 {
	name, _ := extraMeta.(string)
	if name == "" {
		return nil
	}
	// Use a scratch sample to collect the attribute index from AttrTableManager.
	tmp := pprofile.NewSample()
	attrMgr.AppendOptionalString(tmp.AttributeIndices(), attribute.Key("process.name"), name)
	indices := make([]int32, tmp.AttributeIndices().Len())
	for i := range indices {
		indices[i] = tmp.AttributeIndices().At(i)
	}
	return indices
}

// TestProcessMetaEnricherPipeline verifies that values set by a ProcessMetaEnricher
// (stored in TraceEventMeta.ExtraMeta) flow through CollectExtraSampleMeta and
// ExtraSampleAttrs and end up as attributes in the generated profiles.
func TestProcessMetaEnricherPipeline(t *testing.T) {
	cfg := &Config{
		Name:                "test-agent",
		Version:             "v1.0.0",
		SamplesPerSecond:    100,
		ExtraSampleAttrProd: &processNameAttrProducer{},
	}
	reporter := createTestBaseReporter(t, cfg)

	trace := &libpf.Trace{
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 1)
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x1000,
				FunctionName:    libpf.Intern("main"),
			})
			return frames
		}(),
	}

	now := time.Now()
	// Simulate what a ProcessMetaEnricher would have stored in ExtraMeta at
	// process discovery time, which then flows into TraceEventMeta.ExtraMeta.
	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.UnixNano()),
		Comm:           libpf.Intern("myapp"),
		ExecutablePath: libpf.Intern("/usr/bin/myapp"),
		ContainerID:    libpf.Intern("container-x"),
		PID:            3000,
		TID:            3001,
		CPU:            0,
		ExtraMeta:      map[string]string{"process.name": "myapp"},
	}

	err := reporter.ReportTraceEvent(trace, meta)
	require.NoError(t, err)

	eventsTreePtr := reporter.traceEvents.RLock()
	eventsTree := *eventsTreePtr
	reporter.traceEvents.RUnlock(&eventsTreePtr)

	profiles, err := reporter.pdata.Generate(
		eventsTree,
		reporter.name,
		reporter.version,
		reporter.collectionStartTime,
		time.Now(),
	)
	require.NoError(t, err)
	require.NotNil(t, profiles)

	// Verify "process.name" = "myapp" appears in the attribute table.
	dic := profiles.Dictionary()
	strTable := dic.StringTable()
	attrTable := dic.AttributeTable()

	found := false
	for i := 0; i < attrTable.Len(); i++ {
		attr := attrTable.At(i)
		keyIdx := int(attr.KeyStrindex())
		if keyIdx < strTable.Len() && strTable.At(keyIdx) == "process.name" {
			if attr.Value().Str() == "myapp" {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "expected process.name=myapp in the attribute table")
}
