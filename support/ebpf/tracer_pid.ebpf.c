#include "bpfdefs.h"

struct tracer_pid_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} tracer_pid_m SEC(".maps");

SEC("uprobe")
int store_tracer_pid(UNUSED void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 key      = 0;
  bpf_map_update_elem(&tracer_pid_m, &key, &pid, BPF_ANY);
  return 0;
}
