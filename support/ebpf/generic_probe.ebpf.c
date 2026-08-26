#include "bpfdefs.h"
#include "tracemgmt.h"

static EBPF_INLINE int probe__generic(struct pt_regs *ctx, u16 origin_id, u64 value)
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

  return collect_trace(ctx, origin_id, pid, tid, ts, value);
}

// origin_id_probe is set during load time.
BPF_RODATA_VAR(u16, origin_id_probe, 0)

// ext_probe_value enables external probes to forward values
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
  return probe__generic(ctx, origin_id_probe, *value);
}
