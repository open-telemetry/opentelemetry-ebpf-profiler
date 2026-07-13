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
// USDT argument helpers
// ─────────────────────────────────────────────────────────────────────────

static EBPF_INLINE u64 usdt_arg0(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg1(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->si;
#elif defined(__aarch64__)
  return ctx->regs[1];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg2(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->dx;
#elif defined(__aarch64__)
  return ctx->regs[2];
#else
  #error "Unsupported architecture"
#endif
}

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
  u64 user           = usdt_arg0(ctx);
  u64 size           = usdt_arg1(ctx);
  u64 weighted_bytes = usdt_arg2(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid;

  DEBUG_PRINT("heap_usdt: alloc pid=%llu ptr=%llx", pid_tgid >> 32, user);
  DEBUG_PRINT("heap_usdt: alloc size=%llu weighted_bytes=%llu", size, weighted_bytes);

  // We can't use collect_trace() directly: it calls get_pristine_per_cpu_record()
  // internally, which would zero out the ptr/size fields we set below, and its
  // final step is a tail_call() into the unwinder chain that does not return
  // control to us; there is no point after that call where we could still set
  // trace->value_extra before send_trace() fires at the end of the chain.
  // So we inline collect_trace()'s setup here instead, and set our extra
  // fields on the trace immediately after:
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace          = &record->trace;
  trace->origin         = origin_id_heap_alloc;
  trace->pid            = pid;
  trace->tid            = tid;
  trace->ktime          = bpf_ktime_get_ns();
  trace->value          = weighted_bytes;
  trace->value_extra[0] = user;
  trace->value_extra[1] = size;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  // Deliberately not calling push_kernel_frames() here: this is a uprobe, so
  // the process is executing user-space code at the point of the trap, not
  // genuinely running in the kernel. bpf_get_stack()'s kernel-mode stack at
  // this point would just be the uprobe/int3 trap-handling machinery itself,
  // not anything the profiled application was doing; capturing it would
  // mislabel that internal noise as application kernel frames. Contrast with
  // collect_trace()'s callers (kprobes, perf_event overflow), which do fire
  // while the task is genuinely executing in the kernel.

  if (!pid_information_exists(pid)) {
    u64 pid_tgid_val = (u64)pid << 32 | tid;
    if (report_pid(ctx, pid_tgid_val, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }

  int unwinder           = PROG_UNWIND_STOP;
  bool has_usermode_regs = false;
  ErrorCode error        = get_usermode_regs(ctx, &record->state, &has_usermode_regs);
  if (error || !has_usermode_regs) {
    goto exit;
  }

  error = get_next_unwinder_after_native_frame(record, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in uprobe_heap_alloc", unwinder);
  return -1;
}
