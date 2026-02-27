#include "bpfdefs.h"
#include "cupti_activity_bpf.h"
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

// Per-CPU scratch space for large structs that exceed the BPF 512-byte stack limit.
// Used by cuda_kernel_exec and cuda_activity_batch (mutually exclusive on same CPU).
#define MAX_BATCH_SIZE 128
struct cuda_scratch {
  struct kernel_timing timing;
  struct cupti_activity_kernel5 rec;
  u64 ptrs[MAX_BATCH_SIZE];
};

bpf_map_def SEC("maps") cuda_scratch_heap = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(struct cuda_scratch),
  .max_entries = 1,
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

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
  const char *name = (const char *)name_ptr;

  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  struct kernel_timing *timing = &scratch->timing;

  timing->pid            = pid;
  timing->correlation_id = correlation_id;
  timing->start          = start;
  timing->end            = end;
  timing->graph_node_id  = graph_node_id;
  timing->device_id      = device_id;
  timing->stream_id      = stream_id;
  timing->graph_id       = graph_id;

  int chars =
    bpf_probe_read_user_str((char *)&timing->kernel_name, sizeof(timing->kernel_name), name);
  if (chars <= 0) {
    timing->kernel_name[0] = 'e';
    timing->kernel_name[1] = 'r';
    timing->kernel_name[2] = 'r';
    timing->kernel_name[3] = '\0';
  }

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));

  return 0;
}

SEC("usdt/parcagpu/activity_batch")
int BPF_USDT(cuda_activity_batch, u64 ptrs_base, u32 num_activities)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  struct kernel_timing *timing       = &scratch->timing;
  struct cupti_activity_kernel5 *rec = &scratch->rec;

  if (num_activities > MAX_BATCH_SIZE) {
    num_activities = MAX_BATCH_SIZE;
  }

  // Read all activity pointers into scratch space in one shot.
  if (bpf_probe_read_user(scratch->ptrs, num_activities * sizeof(u64), (void *)ptrs_base) != 0) {
    return 0;
  }

  for (u32 i = 0; i < num_activities && i < MAX_BATCH_SIZE; i++) {
    u64 rec_ptr = scratch->ptrs[i & (MAX_BATCH_SIZE - 1)];
    if (rec_ptr == 0) {
      continue;
    }

    // Read the full activity record and filter by kind.
    if (bpf_probe_read_user(rec, sizeof(*rec), (void *)rec_ptr) != 0) {
      continue;
    }
    if (
      rec->kind != CUPTI_ACTIVITY_KIND_KERNEL &&
      rec->kind != CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
      continue;
    }

    timing->pid            = pid;
    timing->correlation_id = rec->correlation_id;
    timing->start          = rec->start;
    timing->end            = rec->end;
    timing->graph_node_id  = rec->graph_node_id;
    timing->device_id      = rec->device_id;
    timing->stream_id      = rec->stream_id;
    timing->graph_id       = rec->graph_id;

    const char *name = (const char *)rec->name_ptr;
    int chars =
      bpf_probe_read_user_str((char *)&timing->kernel_name, sizeof(timing->kernel_name), name);
    if (chars <= 0) {
      timing->kernel_name[0] = 'e';
      timing->kernel_name[1] = 'r';
      timing->kernel_name[2] = 'r';
      timing->kernel_name[3] = '\0';
    }

    bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));
  }

  return 0;
}

// Cookie values for the cuda_probe multi-probe dispatcher.
// Must match the cookie values set in cuda.go.
#define CUDA_PROG_CORRELATION    0
#define CUDA_PROG_KERNEL_EXEC    1
#define CUDA_PROG_ACTIVITY_BATCH 2

// Tail-call prog array for cuda_probe.  Contains a single entry at key 0
// for cuda_activity_batch, whose batch loop pushes past the BPF verifier's
// BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192) limit.  cuda_correlation and
// cuda_kernel_exec are inlined directly in cuda_probe.
bpf_map_def SEC("maps") cuda_progs = {
  .type        = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 1,
};

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 cookie      = (u32)(full_cookie & 0xFFFFFFFF);

  switch (cookie) {
  case CUDA_PROG_CORRELATION: return BPF_USDT_CALL(cuda_correlation, correlation_id, cbid);
  case CUDA_PROG_KERNEL_EXEC:
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
  case CUDA_PROG_ACTIVITY_BATCH: bpf_tail_call(ctx, &cuda_progs, 0); break;
  default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
  }
  return 0;
}
