#include "bpfdefs.h"
#include "types.h"

// report_kallsyms notifies user space about changes to kallsyms.
struct report_kallsyms_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, int);
  __type(value, u32);
  __uint(max_entries, 0);
} report_kallsyms SEC(".maps");

// kprobe__kallsyms notifies user space about changes to kallsyms.
SEC("kprobe/kallsysms")
int kprobe__kallsyms(void *ctx)
{
  u32 value = 1;
  int ret = bpf_perf_event_output(ctx, &report_kallsyms, BPF_F_CURRENT_CPU, &value, sizeof(value));
  if (ret < 0) {
    DEBUG_PRINT("failed to send kallsyms event: error %d", ret);
  }
  return 0;
}
