#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE int probe__generic(struct pt_regs *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    return 0;
  }

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, TRACE_PROBE, pid, tid, ts, 0);
}

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  return probe__generic(ctx);
}
