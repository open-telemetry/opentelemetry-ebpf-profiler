// This file contains the code and map definitions that are used in integration tests only.

#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE void send_sample_traces(void *ctx, u64 pid)
{
  // Use the per CPU record for trace storage: it's too big for stack.
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return; // unreachable
  }

  // Single native frame, no kernel trace.
  Trace *trace = &record->trace;

  // Use COMM as a marker for our test traces. COMM[3] serves as test case ID.
  trace->comm[0] = 0xAA;
  trace->comm[1] = 0xBB;
  trace->comm[2] = 0xCC;

  trace->origin = 1;

  trace->comm[3] = 1;
  trace->pid     = pid;
  trace->tid     = pid;

  u64 *data = push_frame(&record->state, trace, FRAME_MARKER_NATIVE, 0, 21, 1);
  if (data) {
    data[0] = 1337;
  }
  send_trace(ctx, trace);

  // Single native frame, with kernel trace.
  trace->frame_data_len    = 0;
  trace->num_frames        = 0;
  trace->num_kernel_frames = 0;
  trace->comm[3]           = 2;
  push_kernel_frames(ctx, trace);
  data = push_frame(&record->state, trace, FRAME_MARKER_NATIVE, 0, 21, 1);
  if (data) {
    data[0] = 1337;
  }
  send_trace(ctx, trace);
}

// tracepoint_integration__sched_switch captures the kernel stack inline
// and sends sample traces to userspace.
SEC("tracepoint/integration/sched_switch")
int tracepoint_integration__sched_switch(void *ctx)
{
  u64 id  = bpf_get_current_pid_tgid();
  u64 pid = id >> 32;

  printt("pid %lld in integration test", pid);

  send_sample_traces(ctx, pid);

  return 0;
}
