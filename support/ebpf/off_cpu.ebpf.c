#include "bpfdefs.h"
#include "types.h"
#include "tracemgmt.h"

// kprobe_progs maps from a program ID to a kprobe eBPF program
bpf_map_def SEC("maps") kprobe_progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// profile_off_cpu communicates scheduler tasks.
bpf_map_def SEC("maps") profile_off_cpu = {
  .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
  .key_size = sizeof(u64),   // pid_tgid
  .value_size = sizeof(u64), // time in ns
  .max_entries = 256,
};

// tracepoint__sched_switch serves as entry point for off cpu profiling.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(void *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u32 key = 0;
  SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
  if (!syscfg) {
    // Unreachable: array maps are always fully initialized.
    return ERR_UNREACHABLE;
  }

  if (bpf_get_prandom_u32()%OFF_CPU_THRESHOLD_MAX > syscfg->off_cpu_threshold) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  if (bpf_map_update_elem(&profile_off_cpu, &pid_tgid, &ts, BPF_ANY)<0){
      return 0;
  }

  return 0;
}

// dummy is never loaded or called. It just makes sure kprobe_progs is referenced
// and make the compiler and linker happy.
SEC("kprobe/dummy")
int dummy(struct pt_regs *ctx) {
    bpf_tail_call(ctx, &kprobe_progs,0);
    return 0;
}

// kp__finish_task_switch is triggered right after the scheduler updated
// the CPU registers.
SEC("kprobe/finish_task_switch")
int finish_task_switch(struct pt_regs *ctx) {
  // Get the PID and TGID register.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  u64 *start_ts = bpf_map_lookup_elem(&profile_off_cpu, &pid_tgid);
  if (!start_ts){
    // There is no information from the sched/sched_switch entry hook.
    return 0;
  }

  DEBUG_PRINT("==== finish_task_switch ====");

  u64 diff = ts - *start_ts;

  return collect_trace(ctx, TRACE_OFF_CPU, pid, tid, diff);
}