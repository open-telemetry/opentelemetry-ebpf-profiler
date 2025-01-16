// This file contains the code and map definitions for the tracepoint on the scheduler to
// report the stopping a process.

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

// tracepoint__sched_process_exit is a tracepoint attached to the scheduler that stops processes.
// Every time a processes stops this hook is triggered.
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_process_exit(void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = (u32)(pid_tgid >> 32);
  u32 tid      = (u32)(pid_tgid & 0xFFFFFFFF);

  if (pid != tid) {
    // Only if the thread group ID matched with the PID the process itself exits. If they don't
    // match only a thread of the process stopped and we do not need to report this PID to
    // userspace for further processing.
    goto exit;
  }

  if (!bpf_map_lookup_elem(&reported_pids, &pid) && !pid_information_exists(ctx, pid)) {
    // Only report PIDs that we explicitly track. This avoids sending kernel worker PIDs
    // to userspace.
    goto exit;
  }

  if (report_pid(ctx, pid, RATELIMIT_ACTION_RESET)) {
    increment_metric(metricID_NumProcExit);
  }
exit:
  return 0;
}
