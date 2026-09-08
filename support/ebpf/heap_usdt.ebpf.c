// SPDX-License-Identifier: Apache-2.0
//
// USDT (uprobe) handler for heap allocation profiling.
//
// Provider:  "otel_memory" — the current provider emitted by the reference
//            sampler implementation; expected to track the eventual
//            OTel-standard memory-profiling provider name once defined.
//
// Probe:     alloc(void *user, uint64_t size, uint64_t weighted_bytes)
//
// This program is attached PID-scoped from userspace by the `usdt`
// package once per (process, probe site) discovered via .note.stapsdt
// scanning.
//
// v1 reads arguments directly out of pt_regs using the architecture-specific
// register layout, matching the fixed tracepoint signatures emitted by the
// sampler. Honouring per-arg location descriptors from the SDT note is
// follow-up work.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_heap_alloc is set during load time by the heap probe's Load()
// method via the origin registry.
BPF_RODATA_VAR(u16, origin_id_heap_alloc, 0)

// ─────────────────────────────────────────────────────────────────────────
// USDT argument accessors: the registers holding the first three integer
// arguments per the SysV/AAPCS calling conventions, read as ctx->usdt_argN.
// ─────────────────────────────────────────────────────────────────────────
#if defined(__x86_64__)
  #define usdt_arg0 di
  #define usdt_arg1 si
  #define usdt_arg2 dx
#elif defined(__aarch64__)
  #define usdt_arg0 regs[0]
  #define usdt_arg1 regs[1]
  #define usdt_arg2 regs[2]
#else
  #error "Unsupported architecture"
#endif

// ─────────────────────────────────────────────────────────────────────────
// heap:alloc(user, size, weighted_bytes)
//
//   arg0 = user-visible allocation pointer
//   arg1 = allocation size in bytes
//   arg2 = weighted_bytes (unbiased byte estimate; see ADR 00003)
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_alloc")
int uprobe_heap_alloc(struct pt_regs *ctx)
{
  u64 user           = ctx->usdt_arg0;
  u64 size           = ctx->usdt_arg1;
  u64 weighted_bytes = ctx->usdt_arg2;

  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    return 0;
  }

  DEBUG_PRINT("heap_usdt: alloc pid=%u ptr=%llx", pid, user);
  DEBUG_PRINT("heap_usdt: alloc size=%llu weighted_bytes=%llu", size, weighted_bytes);

  // Reserve context values for the weighted byte value, allocation pointer,
  // and raw size. They lead variable_data, ahead of the native frames
  // unwinding appends.
  PerCPURecord *record =
    prepare_trace(origin_id_heap_alloc, pid, tid, group_leader, bpf_ktime_get_ns(), 3);
  if (!record) {
    return 0;
  }
  u64 *values = trace_context_values(&record->trace);
  values[0]   = weighted_bytes;
  values[1]   = user;
  values[2]   = size;

  // Deliberately not capturing kernel frames here: this is a uprobe, so
  // the process is executing user-space code at the point of the trap, not
  // genuinely running in the kernel. bpf_get_stack()'s kernel-mode stack at
  // this point would just be the uprobe/int3 trap-handling machinery itself,
  // not anything the profiled application was doing; capturing it would
  // mislabel that internal noise as application kernel frames. Contrast with
  // collect_trace()'s callers (kprobes, perf_event overflow), which do fire
  // while the task is genuinely executing in the kernel.
  return unwind_trace(ctx, record, false);
}
