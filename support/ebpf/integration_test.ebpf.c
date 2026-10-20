// This file contains the code and map definitions that are used in integration tests only.

#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE void
send_sample_trace(void *ctx, u32 pid, u32 tid, u8 test_case, bool capture_kernel_frames)
{
  PerCPURecord *record = prepare_trace(origin_id_sampling, pid, tid, 0, bpf_ktime_get_ns());
  if (!record) {
    return;
  }

  Trace *trace = &record->trace;

  // Use COMM as a marker for our test traces. COMM[3] serves as test case ID.
  trace->comm[0] = 0xAA;
  trace->comm[1] = 0xBB;
  trace->comm[2] = 0xCC;
  trace->comm[3] = test_case;
  // Context values precede any kernel and user frames. Without kernel frames,
  // push none, like sampling. With kernel frames, push
  // sentinels to verify they survive stack capture and userspace decoding.
  if (capture_kernel_frames) {
    u64 *values = push_context_values(trace, 3);
    if (!values) {
      return;
    }
    values[0] = 0x123456789abcdef0;
    values[1] = 0x2222222222222222;
    values[2] = 0x3333333333333333;
    push_kernel_frames(ctx, trace);
  }

  u64 *data = push_frame(&record->state, trace, FRAME_MARKER_NATIVE, 0, 21, 1);
  if (data) {
    data[0] = 1337;
  }
  trace->frame_data_end = end_variable_data(trace, sizeof(u64));
  send_trace(ctx, trace);
}

SEC("tracepoint/integration/sched_switch")
int tracepoint_integration__sched_switch(void *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    return 0;
  }

  printt("pid %d in integration test", pid);
  send_sample_trace(ctx, pid, tid, 1, false);
  send_sample_trace(ctx, pid, tid, 2, true);
  return 0;
}
