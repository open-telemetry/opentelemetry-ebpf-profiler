#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// kprobe_progs maps from a program ID to a generic probe eBPF program.
struct kprobe_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, NUM_TRACER_PROGS);
} kprobe_progs SEC(".maps");

// tracepoint_progs maps from a program ID to a tracepoint eBPF program.
struct tracepoint_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, NUM_TRACER_PROGS);
} tracepoint_progs SEC(".maps");

// off_cpu_traces holds traces captured when a task switches out until that task
// is scheduled again and its off-CPU duration is known.
struct off_cpu_traces_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u32); // host TID
  __type(value, Trace);
  __uint(max_entries, 256); // adjusted at load time in loadAllMaps.
} off_cpu_traces SEC(".maps");

// sched_times is used by the optional tracepoint+kprobe mode to keep the
// switch-out timestamp until finish_task_switch runs for the task.
struct sched_times_t {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, u64);         // pid_tgid
  __type(value, u64);       // time in ns
  __uint(max_entries, 256); // adjusted at load time
} sched_times SEC(".maps");

// off_cpu_threshold is set during load time.
BPF_RODATA_VAR(u32, off_cpu_threshold, 0)

// origin_id_off_cpu is set during load time.
BPF_RODATA_VAR(u16, origin_id_off_cpu, 0)

// task_pid_offset is resolved from kernel BTF during load time.
BPF_RODATA_VAR(u32, task_pid_offset, 0)

// Stable 64-bit layout of the sched/sched_switch tracepoint payload. Only
// next_pid is consumed, but the preceding fields establish its byte offset.
struct sched_switch_args {
  u64 common;
  u8 prev_comm[16];
  u32 prev_pid;
  s32 prev_prio;
  s64 prev_state;
  u8 next_comm[16];
  u32 next_pid;
  s32 next_prio;
};

static EBPF_INLINE int sched_switch(void *ctx, u32 next_tid)
{
  u64 ts = bpf_ktime_get_ns();

  // Complete a previously captured trace for the task being switched in.
  Trace *stored_trace = bpf_map_lookup_elem(&off_cpu_traces, &next_tid);
  if (stored_trace) {
    if (ts >= stored_trace->ktime) {
      stored_trace->value = ts - stored_trace->ktime;
      stored_trace->ktime = ts;
      send_trace(ctx, stored_trace);
    }
    bpf_map_delete_elem(&off_cpu_traces, &next_tid);
  }

  // The tracepoint fires in the context of the task being switched out, so its
  // userspace memory and saved registers are available to the custom unwinder.
  u64 host_pid_tgid = bpf_get_current_pid_tgid();
  u32 host_tid      = host_pid_tgid;
  if (host_tid == 0) {
    return 0;
  }

  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid) || pid == 0 || tid == 0) {
    return 0;
  }

  if (bpf_get_prandom_u32() > off_cpu_threshold) {
    return 0;
  }

  // value temporarily carries the host TID to unwind_stop, which stores the
  // completed trace. It is replaced by the duration before the trace is sent.
  return collect_trace_from_current_task(
    (struct pt_regs *)ctx, origin_id_off_cpu, pid, tid, ts, host_tid);
}

// tracepoint__sched_switch is the compatibility entry point for kernels that
// do not support BTF-enabled raw tracepoints.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(struct sched_switch_args *ctx)
{
  return sched_switch(ctx, ctx->next_pid);
}

// tp_btf__sched_switch is preferred when supported: it avoids copying the
// regular tracepoint payload and provides the next task directly.
SEC("tp_btf/sched_switch")
int tp_btf__sched_switch(u64 *ctx)
{
  struct task_struct *next = (struct task_struct *)ctx[2];
  u32 next_tid             = 0;
  bpf_probe_read_kernel(&next_tid, sizeof(next_tid), (u8 *)next + task_pid_offset);
  return sched_switch(ctx, next_tid);
}

// tracepoint__sched_switch_legacy is the switch-out half of the previous
// tracepoint+kprobe implementation. The matching kprobe unwinds on switch-in.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch_legacy(UNUSED void *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid) || pid == 0 || tid == 0) {
    return 0;
  }

  if (bpf_get_prandom_u32() > off_cpu_threshold) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  if (process_is_too_new(ts)) {
    return 0;
  }

  u64 pid_tgid = ((u64)pid << 32) | tid;
  if (bpf_map_update_elem(&sched_times, &pid_tgid, &ts, BPF_ANY) < 0) {
    DEBUG_PRINT("Failed to record sched_switch event entry");
  }
  return 0;
}

// finish_task_switch is the switch-in half of tracepoint+kprobe mode.
SEC("kprobe/finish_task_switch")
int finish_task_switch(struct pt_regs *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid) || pid == 0 || tid == 0) {
    return 0;
  }

  u64 pid_tgid  = ((u64)pid << 32) | tid;
  u64 *start_ts = bpf_map_lookup_elem(&sched_times, &pid_tgid);
  if (!start_ts || *start_ts == 0) {
    return 0;
  }

  u64 ts   = bpf_ktime_get_ns();
  u64 diff = ts - *start_ts;
  bpf_map_delete_elem(&sched_times, &pid_tgid);
  return collect_trace(ctx, origin_id_off_cpu, pid, tid, ts, diff);
}

// tracepoint__dummy is never loaded or called. It keeps tracepoint_progs
// referenced in the linked BPF object; actual map references are rewritten at
// load time.
SEC("tracepoint/dummy")
int tracepoint__dummy(void *ctx)
{
  int key = 0;
  if (bpf_map_lookup_elem(&per_cpu_records_kp, &key))
    bpf_tail_call(ctx, &tracepoint_progs, 0);
  return 0;
}

// kprobe__dummy keeps kprobe_progs and per_cpu_records_kp referenced for
// generic kprobe/uprobe profiling. It is never loaded or called.
SEC("kprobe/dummy")
int kprobe__dummy(struct pt_regs *ctx)
{
  int key = 0;
  if (bpf_map_lookup_elem(&per_cpu_records_kp, &key))
    bpf_tail_call(ctx, &kprobe_progs, 0);
  return 0;
}
