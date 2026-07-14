// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "github.com/toliu/opentelemetry-ebpf-profiler/reporter"

import (
	"context"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf/xsync"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/internal/pdata"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"github.com/toliu/opentelemetry-ebpf-profiler/support"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// memRunLoop handles the mem run loop
	memRunLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[libpf.PID, string]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[libpf.Origin]samples.KeyToEventMapping]

	memTraceEvents xsync.RWMutex[map[libpf.Origin]samples.KeyToEventMapping]

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// memAddr-hash
	addrHashMap map[int64]libpf.TraceHash
}

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
	b.memRunLoop.Stop()
}

func (b *baseReporter) ReportHostMetadata(metadataMap map[string]string) {
	b.addHostmetadata(metadataMap)
}

func (b *baseReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	b.addHostmetadata(metadataMap)
	return nil
}

// addHostmetadata adds to and overwrites host metadata.
func (b *baseReporter) addHostmetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		b.hostmetadata.Add(k, v)
	}
}

// ReportFramesForTrace is a NOP
func (*baseReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP
func (b *baseReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *samples.TraceEventMeta) {
}

func (b *baseReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := b.pdata.Executables.GetAndRefresh(fileID, pdata.ExecutableCacheLifetime)
	return known
}

func (b *baseReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := b.pdata.Frames.GetAndRefresh(frameID.FileID(),
		pdata.FramesCacheLifetime); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

func (b *baseReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	b.pdata.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

func (*baseReporter) SupportsReportTraceEvent() bool { return true }

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	if meta.Origin != support.TraceOriginSampling && meta.Origin != support.TraceOriginOffCPU && meta.Origin != support.TraceOriginHeap {
		// At the moment only on-CPU and off-CPU traces are reported.
		log.Errorf("Skip reporting trace for unexpected %d origin", meta.Origin)
		return
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}
	keyHash := trace.Hash
	if meta.MemAlloc > 0 {
		if meta.MemAddr > 0 {
			if meta.OffTime == 1 { // mem-alloc
				b.addrHashMap[meta.MemAddr] = keyHash
			}
			if meta.OffTime == 0 { // mem-free需要在这里找到分配内存的调用栈后续才能关联
				hash, ok := b.addrHashMap[meta.MemAddr]
				if !ok {
					return
				}
				delete(b.addrHashMap, meta.MemAddr)
				keyHash = hash
			}
		}
		//不同的线程ID，导致key不一样，无法将栈进行合并,内存剖析不上报线程了。
		meta.TID = 0
		extraMeta = uint64(meta.PID.Hash32())<<32 | uint64(meta.TID.Hash32()) // NOTE this logic is from cloudcapture
		// FIXME when you debug locally, use this，extraMeta just set tp hash
		//extraMeta = keyHash
	}

	containerID, err := libpf.LookupCgroupv2(b.cgroupv2ID, meta.PID)
	if err != nil {
		log.Tracef("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}
	key := samples.TraceAndMetaKey{
		Hash:           keyHash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
		ExtraMeta:      extraMeta,
	}
	if meta.Origin == support.TraceOriginHeap {
		traceEventsMap := b.memTraceEvents.WLock()
		defer b.memTraceEvents.WUnlock(&traceEventsMap)
		var allocSpaces, allocs, inuseSpaces, inuseAllocs int64
		if meta.OffTime == 0 { // free
			inuseSpaces = -meta.MemAlloc
			inuseAllocs = -1
		} else { // alloc
			allocSpaces = meta.MemAlloc
			allocs = 1
			if meta.MemAddr > 0 {
				inuseSpaces = meta.MemAlloc
				inuseAllocs = 1
			}
		}
		events, exists := (*traceEventsMap)[meta.Origin][key]
		// 只有申请内存的时候才新创建event,如果是释放内存但是没有event说明这个地址是开启profile之前申请的，忽略掉
		if !exists {
			if meta.OffTime != 0 {
				events = &samples.TraceEvents{
					Files:              trace.Files,
					Linenos:            trace.Linenos,
					FrameTypes:         trace.FrameTypes,
					MappingStarts:      trace.MappingStart,
					MappingEnds:        trace.MappingEnd,
					MappingFileOffsets: trace.MappingFileOffsets,
					Timestamps:         []uint64{0}, // 只记录最新的时间
				}
				if meta.MemAddr > 0 {
					events.MemAlloc = []int64{0, 0, 0, 0}
				} else {
					events.MemAlloc = []int64{0, 0, -1, -1} // 不支持inuse
				}
			} else {
				return
			}
		}
		newTimestamp := uint64(meta.Timestamp)
		if events.Timestamps[0] < newTimestamp {
			events.Timestamps[0] = newTimestamp
		}
		events.MemAlloc[0] += allocSpaces
		events.MemAlloc[1] += allocs
		events.MemAlloc[2] += inuseSpaces
		events.MemAlloc[3] += inuseAllocs
		(*traceEventsMap)[meta.Origin][key] = events
		return
	}

	traceEventsMap := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&traceEventsMap)

	if events, exists := (*traceEventsMap)[meta.Origin][key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		(*traceEventsMap)[meta.Origin][key] = events
		return
	}

	(*traceEventsMap)[meta.Origin][key] = &samples.TraceEvents{
		Files:              trace.Files,
		Linenos:            trace.Linenos,
		FrameTypes:         trace.FrameTypes,
		MappingStarts:      trace.MappingStart,
		MappingEnds:        trace.MappingEnd,
		MappingFileOffsets: trace.MappingFileOffsets,
		Timestamps:         []uint64{uint64(meta.Timestamp)},
		OffTimes:           []int64{meta.OffTime},
	}
}

func (b *baseReporter) FrameMetadata(args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	log.Tracef("FrameMetadata [%x] %v+%v at %v:%v",
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
