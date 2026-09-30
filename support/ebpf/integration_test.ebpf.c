// This file contains the code and map definitions that are used in integration tests only.

#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE void
send_sample_trace(void *ctx, u32 pid, u32 tid, u8 test_case, bool capture_kernel_frames)
{
  // Use the per CPU record for trace storage: it's too big for stack.
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return; // unreachable
  }

  Trace *trace = &record->trace;

  // Use COMM as a marker for our test traces. COMM[3] serves as test case ID.
  bpf_get_current_comm(trace->comm, sizeof(trace->comm));
  trace->comm[0] = 0xAA;
  trace->comm[1] = 0xBB;
  trace->comm[2] = 0xCC;
  trace->comm[3] = test_case;
  trace->origin  = origin_id_sampling;
  trace->pid     = pid;
  trace->tid     = tid;

  if (capture_kernel_frames) {
    // Verify that kernel-stack capture preserves a leading context value.
    push_context_value(trace, 0x123456789abcdef0);
    push_kernel_frames(ctx, trace);
  }

  u64 *data = push_frame(&record->state, trace, FRAME_MARKER_NATIVE, 0, 21, 1);
  if (data) {
    data[0] = 1337;
  }
  trace->frame_data_end = trace->variable_data_end;
  send_trace(ctx, trace);
}

static EBPF_INLINE int run_sample_trace(void *ctx, u8 test_case, bool capture_kernel_frames)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    return 0;
  }

  printt("pid %d in integration test", pid);
  send_sample_trace(ctx, pid, tid, test_case, capture_kernel_frames);
  return 0;
}

SEC("tracepoint/integration/sched_switch_no_kernel")
int tracepoint_integration__sched_switch_no_kernel(void *ctx)
{
  return run_sample_trace(ctx, 1, false);
}

SEC("tracepoint/integration/sched_switch_with_kernel")
int tracepoint_integration__sched_switch_with_kernel(void *ctx)
{
  return run_sample_trace(ctx, 2, true);
}
