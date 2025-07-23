#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// uprobe_progs maps from a program ID to a uprobe eBPF program
bpf_map_def SEC("maps") uprobe_progs = {
  .type        = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// uprobe__dummy is never loaded or called. It just makes sure uprobe_progs is
// referenced and make the compiler and linker happy.
SEC("uprobe/dummy")
int uprobe__dummy(struct pt_regs *ctx)
{
  bpf_tail_call(ctx, &uprobe_progs, 0);
  return 0;
}

// uprobe__generic serves as entry point for uprobe based profiling.
SEC("uprobe/generic")
int uprobe__generic(void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, TRACE_UPROBE, pid, tid, ts, 0);
}
