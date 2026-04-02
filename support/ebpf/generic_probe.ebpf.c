#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_generic_probe is set during load time.
BPF_RODATA_VAR(u32, origin_id_generic_probe, 0)

static EBPF_INLINE int probe__generic(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, origin_id_generic_probe, pid, tid, ts, 0);
}

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  return probe__generic(ctx);
}
