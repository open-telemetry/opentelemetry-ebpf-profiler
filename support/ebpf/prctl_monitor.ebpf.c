// This file contains the code for the tracepoint on prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)
// to detect when a process names an anonymous memory mapping "OTEL_CTX".

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

#ifndef TESTING_COREDUMP

  // prctl constants from include/uapi/linux/prctl.h
  #define PR_SET_VMA           0x53564d41
  #define PR_SET_VMA_ANON_NAME 0

// See /sys/kernel/tracing/events/syscalls/sys_enter_prctl/format
struct sys_enter_prctl_ctx {
  unsigned char skip[16]; // common fields (8) + __syscall_nr (4) + pad (4)
  unsigned long option;   // prctl option
  unsigned long arg2;     // sub-option (PR_SET_VMA_ANON_NAME for PR_SET_VMA)
  unsigned long arg3;     // addr
  unsigned long arg4;     // len
  unsigned long arg5;     // name (user-space pointer)
};

// tracepoint__sys_enter_prctl hooks prctl() calls to detect when a process
// names an anonymous VMA "OTEL_CTX". This triggers a PID resynchronization
// so the profiler can discover the newly published process context mapping.
SEC("tracepoint/syscalls/sys_enter_prctl")
int tracepoint__sys_enter_prctl(struct sys_enter_prctl_ctx *ctx)
{
  if (ctx->option != PR_SET_VMA || ctx->arg2 != PR_SET_VMA_ANON_NAME) {
    goto exit;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  if (!bpf_map_lookup_elem(&reported_pids, &pid) && !pid_information_exists(pid)) {
    // Only report PIDs that we explicitly track. This avoids sending kernel worker PIDs
    // to userspace.
    goto exit;
  }

  // Read the VMA name from user-space. We only need 9 bytes ("OTEL_CTX" + NUL).
  __attribute__((aligned(8))) char name[9] = {};
  if (bpf_probe_read_user(name, sizeof(name), (void *)ctx->arg5)) {
    goto exit;
  }

  // Check for an exact "OTEL_CTX" match. We avoid bpf_strncmp (kernel 5.17+).
  // Instead, compare as a u64 for the 8 characters plus a byte check for the
  // NUL terminator.
  if (*(u64 *)name != *(u64 *)"OTEL_CTX" || name[8] != '\0') {
    goto exit;
  }

  if (report_pid(ctx, pid_tgid, RATELIMIT_ACTION_DEFAULT)) {
    increment_metric(metricID_NumPrctlSetVmaOtelCtx);
  }

exit:
  return 0;
}

#endif
