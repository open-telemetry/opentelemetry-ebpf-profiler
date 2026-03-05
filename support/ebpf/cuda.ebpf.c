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
#define PTR_BATCH      16
struct cuda_scratch {
  struct kernel_timing timing;
  struct cupti_activity_kernel5 rec;
  // Pre-parsed activity_batch USDT args, set by cuda_probe before tail call.
  // bpf_get_attach_cookie does not return the correct cookie after bpf_tail_call,
  // so we parse args in cuda_probe and pass them via scratch.
  u64 ab_ptrs_base;
  u32 ab_num_activities;
};

struct cuda_scratch_heap_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cuda_scratch);
  __uint(max_entries, 1);
} cuda_scratch_heap SEC(".maps");

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

  DEBUG_PRINT("cuda_kernel_exec: pid=%u corr_id=%u dev=%u", pid, correlation_id, device_id);

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

  DEBUG_PRINT("cuda_activity_batch: pid=%u num=%u", pid, (u32)num_activities);
  DEBUG_PRINT("cuda_activity_batch: ptrs_base=0x%llx", ptrs_base);

  if (num_activities > MAX_BATCH_SIZE) {
    num_activities = MAX_BATCH_SIZE;
  }

  // Stack-local pointer batch — small enough for the BPF stack.
  u64 ptrs[PTR_BATCH] = {};

  // Nested loop: outer iterates over batches of PTR_BATCH pointers,
  // inner processes each pointer in the batch.  This keeps the verifier's
  // jump-sequence count well under BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192).
  for (u32 batch = 0; batch < MAX_BATCH_SIZE / PTR_BATCH; batch++) {
    u32 base = batch * PTR_BATCH;
    if (base >= num_activities) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= num_activities) {
        break;
      }

      u64 rec_ptr = ptrs[j];

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

      DEBUG_PRINT(
        "cuda_activity_batch: corr_id=%u kind=%u dev=%u",
        rec->correlation_id,
        rec->kind,
        rec->device_id);

      bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, timing, sizeof(*timing));
    }
  }

  return 0;
}

// Tail-call entry point for cuda_activity_batch.  Reads pre-parsed USDT args
// from the scratch map (set by cuda_probe before bpf_tail_call) and forwards
// them to the inline body generated by BPF_USDT.
SEC("usdt/cuda_activity_batch_tail")
int cuda_activity_batch_tail(struct pt_regs *ctx)
{
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  return ____cuda_activity_batch(ctx, scratch->ab_ptrs_base, scratch->ab_num_activities);
}

// Cookie values for the cuda_probe multi-probe dispatcher.
// Must match the cookie values set in cuda.go.
#define CUDA_PROG_CORRELATION    0
#define CUDA_PROG_KERNEL_EXEC    1
#define CUDA_PROG_ACTIVITY_BATCH 2

// Tail-call prog array for cuda_probe.  Contains a single entry at key 0
// for cuda_activity_batch_tail, whose batch loop pushes past the BPF verifier's
// BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192) limit.  cuda_correlation and
// cuda_kernel_exec are inlined directly in cuda_probe.
struct cuda_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cuda_progs;

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
  case CUDA_PROG_ACTIVITY_BATCH: {
    // Parse USDT args before the tail call — bpf_get_attach_cookie does not
    // return the correct cookie after bpf_tail_call.
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      break;
    }
    scratch->ab_ptrs_base      = (u64)bpf_usdt_arg0(ctx);
    scratch->ab_num_activities = (u32)bpf_usdt_arg1(ctx);
    bpf_tail_call(ctx, &cuda_progs, 0);
    break;
  }
  default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
  }
  return 0;
}
