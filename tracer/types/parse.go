// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package types // import "go.opentelemetry.io/ebpf-profiler/tracer/types"

import (
	"fmt"
	"runtime"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// tracerType values identify tracers, such as the native code tracer, or PHP tracer
type tracerType int

const (
	PerlTracer tracerType = iota
	PHPTracer
	PythonTracer
	HotspotTracer
	RubyTracer
	V8Tracer
	DotnetTracer
	GoTracer
	Labels
	BEAMTracer

	// maxTracers indicates the max. number of different tracers
	maxTracers
)

var tracerTypeToName = map[tracerType]string{
	PerlTracer:    "perl",
	PHPTracer:     "php",
	PythonTracer:  "python",
	HotspotTracer: "hotspot",
	RubyTracer:    "ruby",
	V8Tracer:      "v8",
	DotnetTracer:  "dotnet",
	GoTracer:      "go",
	Labels:        "labels",
	BEAMTracer:    "beam",
}

var tracerNameToType = make(map[string]tracerType, maxTracers)

func init() {
	for k, v := range tracerTypeToName {
		tracerNameToType[v] = k
	}
}

// IsMapEnabled checks if the given map is enabled and should be loaded.
func IsMapEnabled(mapName string, includeTracers IncludedTracers) bool {
	switch mapName {
	case "perl_procs":
		return includeTracers.Has(PerlTracer)
	case "php_procs":
		return includeTracers.Has(PHPTracer)
	case "py_procs":
		return includeTracers.Has(PythonTracer)
	case "hotspot_procs":
		return includeTracers.Has(HotspotTracer)
	case "ruby_procs":
		return includeTracers.Has(RubyTracer)
	case "v8_procs":
		return includeTracers.Has(V8Tracer)
	case "dotnet_procs":
		return includeTracers.Has(DotnetTracer)
	case "beam_procs":
		return includeTracers.Has(BEAMTracer)
	case "go_labels_procs", "apm_int_procs":
		// go_labels_procs and apm_int_procs are called from
		// unwind_stop and therefore need to be available all the time.
		return true
	default:
		return true // Not an interpreter map, so it should be loaded
	}
}

// tracerTypeFromName returns the tracer type for the given name.
func tracerTypeFromName(s string) (tracerType, bool) {
	tt, ok := tracerNameToType[s]
	return tt, ok
}

// String returns the tracer's name.
// It returns '<unknown>' in case the tracer is unknown.
func (t tracerType) String() string {
	if result, ok := tracerTypeToName[t]; ok {
		return result
	}

	return "<unknown>"
}

// IncludedTracers holds information about which tracers are enabled.
type IncludedTracers uint16

// String returns a comma-separated list of enabled tracers.
func (t *IncludedTracers) String() string {
	var names []string
	for tracer := range maxTracers {
		if t.Has(tracer) {
			names = append(names, tracer.String())
		}
	}
	return strings.Join(names, ",")
}

// Has returns true if the given tracer is enabled.
func (t *IncludedTracers) Has(tracer tracerType) bool {
	return *t&(1<<tracer) != 0
}

// Enable enables the given tracer.
func (t *IncludedTracers) Enable(tracer tracerType) {
	*t |= 1 << tracer
}

// Disable disables the given tracer.
func (t *IncludedTracers) Disable(tracer tracerType) {
	*t &= ^(1 << tracer)
}

// enableAll enables all known tracers.
func (t *IncludedTracers) enableAll() {
	for tracer := range maxTracers {
		t.Enable(tracer)
	}
}

// enableByName enables the given tracer by its name.
func (t *IncludedTracers) enableByName(name string) bool {
	tracer, ok := tracerTypeFromName(name)
	if ok {
		t.Enable(tracer)
	}
	return ok
}

// Parse parses a string that specifies one or more eBPF tracers to enable.
// Valid inputs are 'all', or any comma-delimited combination of names listed in tracerTypeToName.
// The return value holds the information whether a tracer has been set or not.
// E.g. to check if the Python tracer was requested: `if result.Has(tracertypes.PythonTracer)...`.
func Parse(tracers string) (IncludedTracers, error) {
	var result IncludedTracers

	// Parse and validate tracers string.
	for name := range strings.SplitSeq(tracers, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}

		if result.enableByName(name) {
			continue
		}

		switch name {
		case "all":
			result.enableAll()
			if runtime.GOARCH == "arm64" {
				result.Disable(DotnetTracer)
			}
		case "native":
			log.Warn("Enabling the `native` tracer explicitly is deprecated (it's always-on)")
		default:
			return result, fmt.Errorf("unknown tracer: %s", name)
		}
	}

	if runtime.GOARCH == "arm64" {
		if result.Has(DotnetTracer) {
			result.Disable(DotnetTracer)
			log.Warn("The dotnet tracer is currently not supported on ARM64")
		}
	}

	if tracersEnabled := result.String(); tracersEnabled != "" {
		log.Debugf("Tracer string: %v", tracers)
		log.Infof("Interpreter tracers: %v", tracersEnabled)
	}

	return result, nil
}

// AllTracers is a shortcut that returns an element with all
// tracers enabled.
func AllTracers() IncludedTracers {
	var result IncludedTracers
	result.enableAll()
	return result
}
