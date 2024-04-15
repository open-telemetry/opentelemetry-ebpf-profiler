/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package traceutil

import (
	"hash/fnv"
	"strconv"

	"github.com/elastic/otel-profiling-agent/libpf"
)

// HashTrace calculates the hash of a trace and returns it.
// Be aware that changes to this calculation will break the ability to
// look backwards for the same TraceHash in our backend.
func HashTrace(trace *libpf.Trace) libpf.TraceHash {
	var buf [24]byte
	h := fnv.New128a()
	for i := uint64(0); i < uint64(len(trace.Files)); i++ {
		_, _ = h.Write(trace.Files[i].Bytes())
		// Using FormatUint() or putting AppendUint() into a function leads
		// to escaping to heap (allocation).
		_, _ = h.Write(strconv.AppendUint(buf[:0], uint64(trace.Linenos[i]), 10))
	}
	// make instead of nil avoids a heap allocation
	traceHash, _ := libpf.TraceHashFromBytes(h.Sum(make([]byte, 0, 16)))
	return traceHash
}
