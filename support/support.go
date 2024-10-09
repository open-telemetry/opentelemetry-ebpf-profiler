// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "go.opentelemetry.io/ebpf-profiler/support"

import (
	"bytes"

	cebpf "github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

// LoadCollectionSpec is a wrapper around ebpf.LoadCollectionSpecFromReader and loads the eBPF
// Spec from the embedded file.
// We expect tracerData to hold all possible eBPF maps and programs.
func LoadCollectionSpec(debugTracer bool) (*cebpf.CollectionSpec, error) {
	if debugTracer {
		if len(debugTracerData) > 0 {
			log.Warnf("Using debug eBPF tracers")
			return cebpf.LoadCollectionSpecFromReader(bytes.NewReader(debugTracerData))
		}
		log.Warnf("Debug eBPF tracers not found, using release tracers instead")
	}
	return cebpf.LoadCollectionSpecFromReader(bytes.NewReader(tracerData))
}
