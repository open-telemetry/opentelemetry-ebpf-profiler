package reporter

import (
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
)

type HotspotMemReporter interface {
	ReportHotspotMemProfile()
	StartHotspotMemProfiling(cfg *hotspotmem.OTLPProfilerConfig) error
	StopHotspotMemProfiling(pid int)
	SyncHotspotMemProfilingCfg(cfg *hotspotmem.OTLPProfilerConfig)
}

type MemReporter interface {
	SyncTargetPids(targetPids map[libpf.PID]struct{})
}
