// This file contains the code and map definitions that are used in integration tests only.

#include "bpfdefs.h"

extern bpf_map_def kernel_stackmap;

// kernel_stack_array is used to communicate the kernel stack id to the userspace part of the
// integration test.
bpf_map_def SEC("maps") kernel_stack_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(s32),
  .max_entries = 1,
};


// tracepoint__sched_switch fetches the current kernel stack ID from kernel_stackmap and
// communicates it to userspace via kernel_stack_id map.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(void *ctx) {
  u32 key0 = 0;
  u64 id = bpf_get_current_pid_tgid();
  u64 pid = id >> 32;


  s32 kernel_stack_id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_REUSE_STACKID);

  printt("pid %lld with kernel_stack_id %d", pid, kernel_stack_id);

  if (bpf_map_update_elem(&kernel_stack_array, &key0, &kernel_stack_id, BPF_ANY)) {
    return -1;
  }

  return 0;
}
