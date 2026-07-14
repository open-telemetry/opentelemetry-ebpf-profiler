package reporter

import (
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
)

type HotspotMemReporter interface {
	ReportHotspotMemProfile()
	StartHotspotMemProfiling(cfg *hotspotmem.OTLPProfilerConfig) error
	StopHotspotMemProfiling(pid int)
	SyncHotspotMemProfilingCfg(cfg *hotspotmem.OTLPProfilerConfig)
}
