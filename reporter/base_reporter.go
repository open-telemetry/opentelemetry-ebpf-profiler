// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
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

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// cgroupv2paths caches PID to cgroupv2 path information for cgroupv2 containers.
	cgroupv2paths *lru.SyncedLRU[libpf.PID, string]

	// cgroupv2PathToContainerID caches cgroup v2 path to contaienr ID information.
	cgroupv2PathToContainerID *lru.SyncedLRU[string, string]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]
}

var errUnknownOrigin = errors.New("unknown trace origin")

var (
	// `([0-9a-fA-F]+)`      : This is the main capturing group. It greedily matches
	//                         one or more hexadecimal characters (0-9, a-f, A-F).
	//                         This will capture the full hash regardless of its length.
	// `(?:\.scope)?`        : Non-capturing group that optionally matches the literal
	//                         ".scope" suffix.
	// `$`                   : Anchors the match to the end of the line.
	// This regex effectively finds the last hexadecimal string right before the end
	// of the line, optionally suffixed with ".scope".
	containerIDRegex = regexp.MustCompile(`([0-9a-fA-F]+)(?:\.scope)?$`)
)

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
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

func (b *baseReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := b.pdata.Executables.GetAndRefresh(fileID, pdata.ExecutableCacheLifetime)
	return known
}

func (b *baseReporter) FrameKnown(frameID libpf.FrameID) bool {
	_, known := b.pdata.Frames.GetAndRefresh(frameID, pdata.FrameMapLifetime)
	return known
}

func (b *baseReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	b.pdata.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	if meta.Origin != support.TraceOriginSampling && meta.Origin != support.TraceOriginOffCPU {
		// At the moment only on-CPU and off-CPU traces are reported.
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			errUnknownOrigin)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	cgroupv2Path, err := libpf.LookupCgroupv2(b.cgroupv2paths, meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	containerID := b.extractContainerID(cgroupv2Path)

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
		Tid:            int64(meta.TID),
		ExtraMeta:      extraMeta,
	}

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[samples.ContainerID(containerID)]; !exists {
		(*eventsTree)[samples.ContainerID(containerID)] =
			make(map[libpf.Origin]samples.KeyToEventMapping)
	}

	if _, exists := (*eventsTree)[samples.ContainerID(containerID)][meta.Origin]; !exists {
		(*eventsTree)[samples.ContainerID(containerID)][meta.Origin] =
			make(samples.KeyToEventMapping)
	}

	if events, exists := (*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		(*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key] = events
		return nil
	}
	(*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key] = &samples.TraceEvents{
		Files:              trace.Files,
		Linenos:            trace.Linenos,
		FrameTypes:         trace.FrameTypes,
		MappingStarts:      trace.MappingStart,
		MappingEnds:        trace.MappingEnd,
		MappingFileOffsets: trace.MappingFileOffsets,
		Timestamps:         []uint64{uint64(meta.Timestamp)},
		OffTimes:           []int64{meta.OffTime},
		EnvVars:            meta.EnvVars,
	}
	return nil
}

func (b *baseReporter) FrameMetadata(args *FrameMetadataArgs) {
	log.Debugf("FrameMetadata [%x] %v+%v at %v:%v",
		args.FrameID.FileID(), args.FunctionName, args.FunctionOffset,
		args.SourceFile, args.SourceLine)
	si := samples.SourceInfo{
		LineNumber:     args.SourceLine,
		FilePath:       args.SourceFile,
		FunctionOffset: args.FunctionOffset,
		FunctionName:   args.FunctionName,
	}
	if si.FilePath == "" {
		if oldsi, exists := b.pdata.Frames.Get(args.FrameID); exists {
			si.FilePath = oldsi.FilePath
		}
	}
	b.pdata.Frames.Add(args.FrameID, si)
}

// extractContainerID extracts the container ID from a cgroup v2 path or
// returns an empty string otherwise.
func (b *baseReporter) extractContainerID(cgroupv2Path string) string {
	if v, ok := b.cgroupv2PathToContainerID.GetAndRefresh(cgroupv2Path, 90*time.Second); ok {
		return v
	}
	matches := containerIDRegex.FindStringSubmatch(cgroupv2Path)
	if len(matches) > 1 {
		b.cgroupv2PathToContainerID.Add(cgroupv2Path, matches[1])
		return matches[1]
	}
	b.cgroupv2PathToContainerID.Add(cgroupv2Path, "")
	return ""
}
