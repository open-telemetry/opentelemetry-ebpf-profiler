#include "bpfdefs.h"

// probe_value: per-CPU scratch slot; the entry program stores its u64 payload
// here before tail-calling the collect trampoline. Replaced at load time with
// the per-probe instance created by registerCollectTrampoline.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} probe_value SEC(".maps");

// collect_trace_trampoline: single-entry prog array whose slot 0 holds the
// kprobe__external program ID. Populated at load time via TrampolineProgID().
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} collect_trace_trampoline SEC(".maps");

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  u32 key = 0;
  u64 val = 0;
  bpf_map_update_elem(&probe_value, &key, &val, BPF_ANY);
  bpf_tail_call(ctx, &collect_trace_trampoline, 0);
  return 0;
}
