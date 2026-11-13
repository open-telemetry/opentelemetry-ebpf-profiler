// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"context"
)

// traceEventQueueSize bounds the queued trace operations; a full queue
// blocks producers, applying backpressure to the ringbuf reader.
const traceEventQueueSize = 256

// traceOp is a trace event to process, or a batch boundary.
type traceOp struct {
	// event, when non-nil, is processed by the worker, which returns it to
	// the pool.
	event *traceEvent
	// done, when non-nil, is closed once this and all prior operations were
	// processed; used by tests.
	done chan struct{}
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

// traceWorker processes queued operations in FIFO order, so batch
// boundaries apply only after all prior events were processed.
func (pm *ProcessManager) traceWorker(ctx context.Context) {
	for {
		select {
		case op := <-pm.traceOps:
			switch {
			case op.done != nil:
				close(op.done)
			case op.event != nil:
				pm.processTrace(op.event)
			default:
				pm.batchBoundary()
			}
		case <-ctx.Done():
			return
		}
	}
}
