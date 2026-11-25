// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"context"

	"go.opentelemetry.io/ebpf-profiler/times"
)

// traceEventQueueSize bounds the queued trace events; a full queue blocks
// producers, applying backpressure to the ringbuf reader.
const traceEventQueueSize = 256

// traceOp is a trace event to process, or a cleanup boundary carrying the
// checkpoint time of a consumed ring buffer snapshot.
type traceOp struct {
	// event, when non-nil, is processed by the worker, which returns it to
	// the pool.
	event *traceEvent
	// boundaryKTime is the checkpoint time of a cleanup boundary, which has
	// event nil.
	boundaryKTime times.KTime
}

// submit enqueues op for the trace worker, blocking while the queue is full.
// On shutdown, the operation is dropped.
func (pm *ProcessManager) submit(op traceOp) {
	select {
	case pm.traceOps <- op:
	case <-pm.lifecycleCtx.Done():
		if op.event != nil {
			pm.tracePool.Put(op.event)
		}
	}
}

// traceWorker processes queued operations in FIFO order, so a cleanup
// boundary applies only after all prior events were processed.
func (pm *ProcessManager) traceWorker(ctx context.Context) {
	for {
		select {
		case op := <-pm.traceOps:
			if op.event != nil {
				pm.processTrace(op.event)
			} else {
				pm.processedUntil(op.boundaryKTime)
			}
		case <-ctx.Done():
			return
		}
	}
}
