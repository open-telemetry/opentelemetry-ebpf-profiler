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

// probe_off_cpu_progs maps from a program ID to an off-CPU eBPF program.
struct probe_off_cpu_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, NUM_TRACER_PROGS);
} probe_off_cpu_progs SEC(".maps");

// probe_off_cpu_sched_times is used by the tracepoint+kprobe mode to keep the
// switch-out timestamp until finish_task_switch runs for the task.
struct probe_off_cpu_sched_times_t {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, u64);         // pid_tgid
  __type(value, u64);       // time in ns
  __uint(max_entries, 256); // adjusted at load time
} probe_off_cpu_sched_times SEC(".maps");

// off_cpu_threshold is set during load time.
BPF_RODATA_VAR(u32, off_cpu_threshold, 0)

// origin_id_off_cpu is set during load time.
BPF_RODATA_VAR(u16, origin_id_off_cpu, 0)

static EBPF_INLINE int sched_switch(void *ctx, struct task_struct *next)
{
  u64 ts        = bpf_ktime_get_ns();
  u64 next_task = (u64)next;

  // Complete a previously captured trace for the task being switched in.
  Trace *stored_trace = bpf_map_lookup_elem(&deferred_traces, &next_task);
  if (stored_trace) {
    if (ts >= stored_trace->ktime) {
      stored_trace->value = ts - stored_trace->ktime;
      stored_trace->ktime = ts;
      send_trace(ctx, stored_trace);
    }
    bpf_map_delete_elem(&deferred_traces, &next_task);
  }

  // The tracepoint fires in the context of the task being switched out, so its
  // userspace memory and saved registers are available to the custom unwinder.
  u64 current_task = bpf_get_current_task();
  if (current_task == 0) {
    return 0;
  }

  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader) || pid == 0 || tid == 0) {
    return 0;
  }

  if (bpf_get_prandom_u32() > off_cpu_threshold) {
    return 0;
  }

  // value temporarily carries the task_struct pointer to unwind_stop, which
  // stores the completed trace. It is replaced by the duration before sending.
  return collect_trace_from_current_task(
    (struct pt_regs *)ctx, origin_id_off_cpu, pid, tid, group_leader, ts, current_task);
}

// raw_tracepoint__sched_switch is the compatibility entry point for kernels
// that do not support BTF-enabled raw tracepoints. Raw tracepoints still expose
// the next task pointer, so pending traces never need a reuse-prone TID key.
SEC("raw_tracepoint/sched_switch")
int raw_tracepoint__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
  return sched_switch(ctx, (struct task_struct *)ctx->args[2]);
}

// tp_btf__sched_switch is preferred when supported: it avoids copying the
// regular tracepoint payload and provides the next task directly.
SEC("tp_btf/sched_switch")
int tp_btf__sched_switch(u64 *ctx)
{
  struct task_struct *next = (struct task_struct *)ctx[2];
  return sched_switch(ctx, next);
}

// tracepoint__sched_switch_legacy is the switch-out half of the previous
// tracepoint+kprobe implementation. The matching kprobe unwinds on switch-in.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch_legacy(UNUSED void *ctx)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader) || pid == 0 || tid == 0) {
    return 0;
  }

  if (bpf_get_prandom_u32() > off_cpu_threshold) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  if (process_is_too_new(ts, group_leader)) {
    return 0;
  }

  u64 pid_tgid = ((u64)pid << 32) | tid;
  if (bpf_map_update_elem(&probe_off_cpu_sched_times, &pid_tgid, &ts, BPF_ANY) < 0) {
    DEBUG_PRINT("Failed to record sched_switch event entry");
  }
  return 0;
}

// finish_task_switch is the switch-in half of tracepoint+kprobe mode.
SEC("kprobe/finish_task_switch")
int finish_task_switch(struct pt_regs *ctx)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader) || pid == 0 || tid == 0) {
    return 0;
  }

  u64 pid_tgid  = ((u64)pid << 32) | tid;
  u64 *start_ts = bpf_map_lookup_elem(&probe_off_cpu_sched_times, &pid_tgid);
  if (!start_ts || *start_ts == 0) {
    return 0;
  }

  u64 ts   = bpf_ktime_get_ns();
  u64 diff = ts - *start_ts;
  bpf_map_delete_elem(&probe_off_cpu_sched_times, &pid_tgid);
  return collect_trace(ctx, origin_id_off_cpu, pid, tid, group_leader, ts, diff, false);
}

// tracepoint__dummy is never loaded or called. It keeps probe_off_cpu_progs
// referenced in the linked BPF object; actual map references are rewritten at
// load time.
SEC("tracepoint/dummy")
int tracepoint__dummy(void *ctx)
{
  int key = 0;
  if (bpf_map_lookup_elem(&per_cpu_records_kp, &key))
    bpf_tail_call(ctx, &probe_off_cpu_progs, 0);
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
