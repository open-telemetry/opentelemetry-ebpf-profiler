// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"path/filepath"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// appendSourceProfile appends a probe-produced SourceProfile to the existing
// Profiles object, sharing the same dictionary and ordered sets. One OTLP
// profile is created per (PID, sample-type) combination.
func appendSourceProfile(
	profiles pprofile.Profiles,
	dic pprofile.ProfilesDictionary,
	attrMgr *samples.AttrTableManager,
	stringSet orderedset.OrderedSet[string],
	funcSet orderedset.OrderedSet[funcInfo],
	locationSet orderedset.OrderedSet[locationInfo],
	mappingSet orderedset.OrderedSet[libpf.FrameMapping],
	stackSet orderedset.OrderedSet[stackInfo],
	agentName, agentVersion string,
	collectionStartTime, collectionEndTime time.Time,
	sp samples.SourceProfile,
	processMeta func(libpf.PID) samples.ProcessMeta,
) {
	if len(sp.Samples) == 0 || len(sp.SampleTypes) == 0 {
		return
	}

	// Group samples by PID for per-process resource profiles.
	byPID := make(map[libpf.PID][]samples.SourceSample)
	for _, s := range sp.Samples {
		byPID[s.PID] = append(byPID[s.PID], s)
	}

	durationNanos := uint64(collectionEndTime.Sub(collectionStartTime).Nanoseconds())

	// Build an index of existing ResourceProfiles by PID so we can append
	// profiles to the same resource that holds other profile types.
	rpByPID := make(map[libpf.PID]pprofile.ResourceProfiles)
	for i := range profiles.ResourceProfiles().Len() {
		rp := profiles.ResourceProfiles().At(i)
		pidVal, ok := rp.Resource().Attributes().Get(string(semconv.ProcessPIDKey))
		if ok {
			rpByPID[libpf.PID(pidVal.Int())] = rp
		}
	}

	for pid, pidSamples := range byPID {
		// Try to find the existing ResourceProfiles for this PID.
		rp, found := rpByPID[pid]
		if !found {
			rp = profiles.ResourceProfiles().AppendEmpty()
			attrs := rp.Resource().Attributes()
			attrs.PutInt(string(semconv.ProcessPIDKey), int64(pid))
			if processMeta != nil {
				meta := processMeta(pid)
				if meta.ExecutablePath != libpf.NullString {
					attrs.PutStr(string(semconv.ProcessExecutablePathKey), meta.ExecutablePath.String())
					_, exeName := filepath.Split(meta.ExecutablePath.String())
					attrs.PutStr(string(semconv.ProcessExecutableNameKey), exeName)
				}
				if meta.ContainerID != libpf.NullString {
					attrs.PutStr(string(semconv.ContainerIDKey), meta.ContainerID.String())
				}
			}
		}

		// Find or create a ScopeProfiles within this resource.
		var scope pprofile.ScopeProfiles
		if rp.ScopeProfiles().Len() > 0 {
			scope = rp.ScopeProfiles().At(0)
		} else {
			scope = rp.ScopeProfiles().AppendEmpty()
			s := scope.Scope()
			s.SetName(agentName)
			s.SetVersion(agentVersion)
		}

		// Create one OTLP profile per sample type.
		for stIdx, st := range sp.SampleTypes {
			prof := scope.Profiles().AppendEmpty()

			sampleType := prof.SampleType()
			sampleType.SetTypeStrindex(stringSet.Add(st.Type))
			sampleType.SetUnitStrindex(stringSet.Add(st.Unit))

			for _, entry := range pidSamples {
				sample := prof.Samples().AppendEmpty()
				if stIdx < len(entry.Values) {
					sample.Values().Append(entry.Values[stIdx])
				} else {
					sample.Values().Append(0)
				}
				sample.TimestampsUnixNano().Append(uint64(collectionEndTime.UnixNano()))

				stackIdx := appendFramesAsStack(entry.Frames, dic, attrMgr,
					stringSet, funcSet, mappingSet, locationSet, stackSet)
				sample.SetStackIndex(stackIdx)
			}

			prof.SetDurationNano(durationNanos)
			prof.SetTime(pcommon.Timestamp(collectionStartTime.UnixNano()))
		}
	}
}
