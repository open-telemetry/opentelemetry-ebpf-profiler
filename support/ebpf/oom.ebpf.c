#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_oom is set during load time by the Go probe.
BPF_RODATA_VAR(u16, origin_id_oom, 0)

// oom_kill_process fires when the OOM killer selects and kills a victim.
// The stack trace captured here is the OOM killer's call chain
// (the allocating task that triggered the OOM), not the victim's.
SEC("kprobe/oom_kill_process")
int kprobe__oom_kill_process(struct pt_regs *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, origin_id_oom, pid, tid, ts, 0);
}
