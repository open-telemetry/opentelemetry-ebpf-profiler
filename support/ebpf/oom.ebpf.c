#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_oom is set during load time.
BPF_RODATA_VAR(u32, origin_id_oom, 0)

// oom_kill_process is triggered ...
SEC("kprobe/oom_kill_process")
int oom_kill_process(struct pt_regs *ctx)
{
  // Get the PID and TGID register.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }
  u64 ts = bpf_ktime_get_ns();

  DEBUG_PRINT("==== oom_kill_process ====");

  return collect_trace(ctx, origin_id_oom, pid, tid, ts, 0);
}
