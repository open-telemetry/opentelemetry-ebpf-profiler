// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// uprobe_dlopen fires when a traced process calls dlopen(). It triggers a
// userspace re-scan of /proc/<pid>/maps so newly mapped shared objects
// (notably language interpreters loaded at runtime) become profilable
// promptly instead of waiting for the next periodic refresh.
SEC("uprobe/dlopen")
int uprobe_dlopen(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  increment_metric(metricID_DlopenUprobeHits);

  // RATELIMIT_ACTION_NONE: every dlopen call is interesting; suppression
  // would defeat the purpose of this probe. Unlike RATELIMIT_ACTION_RESET,
  // this also leaves the existing ratelimit token intact so that unrelated
  // periodic PID events for the same process keep their backoff state.
  report_pid(ctx, pid_tgid, RATELIMIT_ACTION_NONE);
  return 0;
}
