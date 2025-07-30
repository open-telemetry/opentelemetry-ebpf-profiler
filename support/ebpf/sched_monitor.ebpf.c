// This file contains the code and map definitions for the tracepoint on the scheduler to
// report the stopping a process.

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

// See /sys/kernel/debug/tracing/events/sched/sched_process_free/format
// for struct layout.
struct sched_process_free_ctx {
  unsigned char skip[24];
  pid_t pid;
  int prio;
};

// tracepoint__sched_process_free is a tracepoint attached to the scheduler that frees processes.
// Every time a processes exits this hook is triggered.
SEC("tracepoint/sched/sched_process_free")
int tracepoint__sched_process_free(struct sched_process_free_ctx *ctx)
{
  u32 pid = ctx->pid;

  if (!bpf_map_lookup_elem(&reported_pids, &pid) && !pid_information_exists(pid)) {
    // Only report PIDs that we explicitly track. This avoids sending kernel worker PIDs
    // to userspace.
    goto exit;
  }

  if (report_pid(ctx, (u64)pid << 32 | pid, RATELIMIT_ACTION_RESET)) {
    increment_metric(metricID_NumProcExit);
  }
exit:
  return 0;
}
