// This file contains the code and map definitions for system configuration
// and analysis related functions.

#include "bpfdefs.h"
#include "extmaps.h"
#include "types.h"

#ifndef TESTING_COREDUMP

// system_analysis is the bpf map the HA and this module uses to communicate
struct system_analysis_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct SystemAnalysis);
  __uint(max_entries, 1);
} system_analysis SEC(".maps");

// read_kernel_memory reads data from given kernel address. This is
// invoked once on entry to bpf() syscall on the given pid context.
SEC("tracepoint/syscalls/sys_enter_bpf")
int read_kernel_memory(UNUSED void *ctx)
{
  u32 key0 = 0;

  struct SystemAnalysis *sys = bpf_map_lookup_elem(&system_analysis, &key0);
  if (!sys) {
    // Not reachable. The one array element always exists.
    return 0;
  }

  if (!is_our_analysis_task(sys->pid)) {
    // Execute the hook only in the context of the requesting task, using the
    // profiler's PID-namespace view so it matches the PID userspace passed in.
    return 0;
  }

  // Handle the read request
  sys->err = bpf_probe_read_kernel(sys->code, sizeof(sys->code), (void *)sys->address);
  if (sys->err) {
    DEBUG_PRINT("Failed to read code from 0x%lx: %ld", (unsigned long)sys->address, (long)sys->err);
  }

  // Mark request handled once the helper has finished populating the result.
  sys->pid = 0;

  return 0;
}

// read_task_struct reads data the current struct task_struct along with
// the struct pt_regs pointer to the entry stack's usermode cpu state.
// Requires kernel 4.19 or newer due to attaching to a raw tracepoint.
SEC("raw_tracepoint/sys_enter")
int read_task_struct(struct bpf_raw_tracepoint_args *ctx)
{
  struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
  u32 key0             = 0;

  struct SystemAnalysis *sys = bpf_map_lookup_elem(&system_analysis, &key0);
  if (!sys) {
    // Not reachable. The one array element always exists.
    return 0;
  }

  if (!is_our_analysis_task(sys->pid)) {
    // Execute the hook only in the context of the requesting task, using the
    // profiler's PID-namespace view so it matches the PID userspace passed in.
    return 0;
  }

  // Request to read current task. Adjust read address, and return
  // also the address of struct pt_regs in the entry stack.
  u64 addr = bpf_get_current_task() + sys->address;

  // As this is a raw tracepoint for syscall entry, the struct pt_regs *
  // is guaranteed to be the user mode cpu state on the entry stack.
  // Return this to the caller.
  sys->address = (u64)regs;

  // Execute the read request.
  sys->err = bpf_probe_read_kernel(sys->code, sizeof(sys->code), (void *)addr);
  if (sys->err) {
    DEBUG_PRINT("Failed to read task_struct from 0x%lx: %ld", (unsigned long)addr, (long)sys->err);
  }

  // Mark request handled once the helper has finished populating the result.
  sys->pid = 0;

  return 0;
}

// read_pid_level discovers the depth of the profiler's own PID namespace.
// Writes group_leader->thread_pid->level (u32) into sys->code[0..4) and clears
// sys->pid to signal completion. Invoked once at startup; userspace then passes
// the value as the profiler_pidns_level rodata var.
SEC("raw_tracepoint/sys_enter")
int read_pid_level(UNUSED struct bpf_raw_tracepoint_args *ctx)
{
  u32 key0                   = 0;
  struct SystemAnalysis *sys = bpf_map_lookup_elem(&system_analysis, &key0);
  if (!sys || !is_our_analysis_task(sys->pid)) {
    return 0;
  }

  void *task = (void *)bpf_get_current_task();
  void *leader;
  sys->err = bpf_probe_read_kernel(&leader, sizeof(leader), task + task_group_leader_offset);
  if (sys->err || !leader) {
    if (!sys->err)
      sys->err = -14; /* -EFAULT */
    sys->pid = 0;
    return 0;
  }

  void *pid;
  sys->err = bpf_probe_read_kernel(&pid, sizeof(pid), leader + task_thread_pid_offset);
  if (sys->err || !pid) {
    if (!sys->err)
      sys->err = -14; /* -EFAULT */
    sys->pid = 0;
    return 0;
  }

  u32 level;
  sys->err = bpf_probe_read_kernel(&level, sizeof(level), pid + pid_level_offset);
  if (!sys->err)
    __builtin_memcpy(sys->code, &level, sizeof(level));
  sys->pid = 0;
  return 0;
}

#endif
