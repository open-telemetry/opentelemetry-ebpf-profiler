#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// Per-CPU array to pass context_value from external programs to custom__generic.
// External programs should:
// 1. Get a reference to this map (via map reuse or pinning)
// 2. Store context_value: bpf_map_update_elem(&custom_context_map, &key0, &context_value, BPF_ANY)
// 3. Tail call to custom__generic
//
// This map can be reused by loading the same eBPF object or via BPF filesystem pinning.
struct custom_context_map_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 1);
} custom_context_map SEC(".maps");

// custom__generic serves as entry point for custom trace profiling with context_value.
// This can be called as a tail call from external eBPF programs.
// Not meant to be attached directly - just loaded for tail calling.
SEC("uprobe/custom__generic")
int custom__generic(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  // Retrieve context_value from the shared per-CPU map
  u32 key0 = 0;
  u64 *context_value_ptr = bpf_map_lookup_elem(&custom_context_map, &key0);
  u64 context_value = context_value_ptr ? *context_value_ptr : 0;

  PerCPURecord *record = get_per_cpu_record();
  if (record) {
    record->tailCalls += 1;
  }

  // Collect trace with TRACE_CUSTOM origin
  // Pass context_value as the last parameter (similar to off_cpu_time for TRACE_OFF_CPU)
  return collect_trace(ctx, TRACE_CUSTOM, pid, tid, ts, context_value);
}
