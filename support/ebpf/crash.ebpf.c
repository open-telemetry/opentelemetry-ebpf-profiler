#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_crash is set during load time by the Go probe.
BPF_RODATA_VAR(u16, origin_id_crash, 0)

// do_coredump fires when a fatal signal with default disposition (core dump)
// kills the process. Covers SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL.
// Runs in the dying thread's context — registers and kernel stack are live.
SEC("kprobe/do_coredump")
int kprobe__do_coredump(struct pt_regs *ctx)
{
  // Try namespace-aware PID first. During do_coredump the process may
  // be in a state where bpf_get_ns_current_pid_tgid() returns -EINVAL,
  // so fall back to the global PID. The trace may have kernel frames
  // only if the host PID isn't in the mapping trie, but that's better
  // than dropping it entirely.
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    tid = (u32)pid_tgid;
  }
  if (pid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, origin_id_crash, pid, tid, ts, 0);
}
