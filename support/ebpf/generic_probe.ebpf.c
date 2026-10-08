#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_probe is set during load time.
BPF_RODATA_VAR(u16, origin_id_probe, 0)

// probe__generic captures a trace, carrying *value as its context value if
// value is non-NULL.
static EBPF_INLINE int probe__generic(struct pt_regs *ctx, const u64 *value)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    return 0;
  }

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  PerCPURecord *record = prepare_trace(origin_id_probe, pid, tid, group_leader, ts, value ? 1 : 0);
  if (!record) {
    return 0;
  }
  if (value) {
    trace_context_values(&record->trace)[0] = *value;
  }
  return unwind_trace(ctx, record, true);
}

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  return probe__generic(ctx, NULL);
}

// ext_probe_value enables externally hosted probes to forward values
// related to the stack unwinding.
struct external_probe_value_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, u64);
  __uint(max_entries, 1);
} ext_probe_value SEC(".maps");

// kprobe__external serves as tail call target for externally hosted probes.
SEC("kprobe/external")
int kprobe__external(struct pt_regs *ctx)
{
  int key    = 0;
  u64 *value = bpf_map_lookup_elem(&ext_probe_value, &key);
  if (!value) {
    DEBUG_PRINT("Failed to read value from ext_probe_value");
    return 0;
  }
  return probe__generic(ctx, value);
}
