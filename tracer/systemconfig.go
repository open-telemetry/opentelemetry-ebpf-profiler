/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

// #include "../support/ebpf/types.h"
import "C"

import (
	"unsafe"

	"github.com/elastic/otel-profiling-agent/config"

	cebpf "github.com/cilium/ebpf"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/pacmask"
	log "github.com/sirupsen/logrus"
)

func loadSystemConfig(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kernelSymbols *libpf.SymbolMap, includeTracers []bool) error {
	pacMask := pacmask.GetPACMask()

	if pacMask != uint64(0) {
		log.Infof("Determined PAC mask to be 0x%016X", pacMask)
	} else {
		log.Debug("PAC is not enabled on the system.")
	}

	// In eBPF, we need the mask to AND off the PAC bits, so we invert it.
	invPacMask := ^pacMask

	var tpbaseOffset uint64
	if includeTracers[config.PerlTracer] || includeTracers[config.PythonTracer] {
		var err error
		tpbaseOffset, err = loadTPBaseOffset(coll, maps, kernelSymbols)
		if err != nil {
			return err
		}
	}

	cfg := C.SystemConfig{
		inverse_pac_mask:       C.u64(invPacMask),
		tpbase_offset:          C.u64(tpbaseOffset),
		drop_error_only_traces: C.bool(true),
	}

	key0 := uint32(0)
	return maps["system_config"].Update(unsafe.Pointer(&key0), unsafe.Pointer(&cfg),
		cebpf.UpdateAny)
}
