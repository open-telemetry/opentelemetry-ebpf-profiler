package dynamicprofiling

import (
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/discovery"
)

type Policy interface {
	ProfilingEnabled(process process.Process, mappings []process.Mapping) bool
}

type AlwaysOnPolicy struct{}

func (a AlwaysOnPolicy) ProfilingEnabled(_ process.Process, _ []process.Mapping) bool {
	return true
}

type ServiceDiscoveryTargetsOnlyPolicy struct {
	Discovery discovery.TargetProducer
}

func (s *ServiceDiscoveryTargetsOnlyPolicy) ProfilingEnabled(
	p process.Process,
	_ []process.Mapping,
) bool {
	target := s.Discovery.FindTarget(uint32(p.PID()))
	return target != nil
}

// things to consider for the future:
//     allow profiling based on exe / cwd name?
//     introduce a specific env variable to enable profiling?
//     introduce a copy of process.relabeling here
