#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// cuda_correlation reads the correlation ID from the USDT probe and records a trace.
SEC("usdt/parcagpu/cuda_correlation")
int BPF_USDT(cuda_correlation, u32 correlation_id, s32 cbid)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  DEBUG_PRINT("cuda_correlation_probe: correlation_id=%u, cbid=%u", correlation_id, cbid);

  u64 ts      = bpf_ktime_get_ns();
  // Cast cbid to s32 first to get sign extension, then to u64
  u64 cuda_id = correlation_id + ((u64)cbid << 32);
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cuda_id);
}

struct kernel_timing {
  u32 pid;
  u32 correlation_id;
  u64 start;
  u64 end;
  u64 graph_node_id;
  u32 device_id;
  u32 stream_id;
  u32 graph_id;
  char kernel_name[256];
};

struct cuda_timing_events_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 0);
} cuda_timing_events SEC(".maps");

SEC("usdt/parcagpu/cuda_kernel")
int BPF_USDT(
  cuda_kernel_exec,
  u64 start,
  u64 end,
  u32 correlation_id,
  u32 device_id,
  u32 stream_id,
  u32 graph_id,
  u64 graph_node_id,
  u64 name_ptr)
{
  u64 pid_tgid     = bpf_get_current_pid_tgid();
  u32 pid          = pid_tgid >> 32;
  u64 duration_ns  = end - start;
  const char *name = (const char *)name_ptr;

  DEBUG_PRINT(
    "cuda_kernel_exec: correlation_id=%u, duration_ns=%llu, name=%s\n",
    correlation_id,
    duration_ns,
    name);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = correlation_id,
    .start          = start,
    .end            = end,
    .graph_node_id  = graph_node_id,
    .device_id      = device_id,
    .stream_id      = stream_id,
    .graph_id       = graph_id,
  };

  // copy name into timing.name
  int chars =
    bpf_probe_read_user_str((char *)&timing.kernel_name, sizeof(timing.kernel_name), name);
  // empty string is a graph launch so put in a sentinel value
  if (chars <= 0) {
    // error reading string
    timing.kernel_name[0] = 'e';
    timing.kernel_name[1] = 'r';
    timing.kernel_name[2] = 'r';
    timing.kernel_name[3] = '\0';
  }

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  // Extract user cookie from low 32 bits (high 32 bits contain spec ID)
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 cookie      = (u32)(full_cookie & 0xFFFFFFFF);
  switch (cookie) {
  case 'c': return BPF_USDT_CALL(cuda_correlation, correlation_id, cbid);
  case 'k':
    return BPF_USDT_CALL(
      cuda_kernel_exec,
      start,
      end,
      correlation_id,
      device_id,
      stream_id,
      graph_id,
      graph_node_id,
      name);
  default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
  }
  return 0;
}
