// This file contains the code for the kprobe that reports the exit of a thread group.

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

// Every time a thread group exits this hook is triggered.
SEC("kprobe/disassociate_ctty")
int disassociate_ctty(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = (u32)(pid_tgid >> 32);

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
