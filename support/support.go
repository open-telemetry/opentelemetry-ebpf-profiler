/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package support

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
