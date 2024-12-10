// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

// BaseReporter is a reporter than handles shared behavior between all the
// available reporters.
type BaseReporter struct {
	cfg *Config

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[libpf.PID, string]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[samples.TraceAndMetaKey]*samples.TraceEvents]
}

func (*BaseReporter) SupportsReportTraceEvent() bool { return true }

// ReportTraceEvent enqueues reported trace events for the reporter.
func (b *BaseReporter) ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta) {
	traceEventsMap := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&traceEventsMap)

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	containerID, err := libpf.LookupCgroupv2(b.cgroupv2ID, meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		Executable:     meta.Executable,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
		ExtraMeta:      extraMeta,
	}

	if events, exists := (*traceEventsMap)[key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = events
		return
	}

	(*traceEventsMap)[key] = &samples.TraceEvents{
		Files:              trace.Files,
		Linenos:            trace.Linenos,
		FrameTypes:         trace.FrameTypes,
		MappingStarts:      trace.MappingStart,
		MappingEnds:        trace.MappingEnd,
		MappingFileOffsets: trace.MappingFileOffsets,
		Timestamps:         []uint64{uint64(meta.Timestamp)},
	}
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (b *BaseReporter) FrameMetadata(args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	log.Debugf("FrameMetadata [%x] %v+%v at %v:%v",
		fileID, args.FunctionName, args.FunctionOffset,
		args.SourceFile, args.SourceLine)

	if frameMapLock, exists := b.pdata.Frames.GetAndRefresh(fileID,
		pdata.FramesCacheLifetime); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		sourceFile := args.SourceFile
		if sourceFile == "" {
			// The new SourceFile may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.FilePath
			}
		}

		(*frameMap)[addressOrLine] = samples.SourceInfo{
			LineNumber:     args.SourceLine,
			FilePath:       sourceFile,
			FunctionOffset: args.FunctionOffset,
			FunctionName:   args.FunctionName,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]samples.SourceInfo)
	v[addressOrLine] = samples.SourceInfo{
		LineNumber:     args.SourceLine,
		FilePath:       args.SourceFile,
		FunctionOffset: args.FunctionOffset,
		FunctionName:   args.FunctionName,
	}
	mu := xsync.NewRWMutex(v)
	b.pdata.Frames.Add(fileID, &mu)
}
