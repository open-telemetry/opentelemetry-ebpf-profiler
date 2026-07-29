#include "bpfdefs.h"

/*
 * BPF_PROG_TYPE_SOCKET_FILTER does not permit bpf_get_current_pid_tgid
 * on kernels older than ~5.13, because that helper is restricted to the
 * tracing helper set.  raw_tracepoint programs use the tracing helper set
 * and have had BPF_PROG_TEST_RUN support since kernel 5.0, so they work
 * across all kernels the profiler supports (>=5.11).
 */
SEC("raw_tracepoint/test") int store_tracer_pid(UNUSED struct bpf_raw_tracepoint_args *ctx)
{
  /* bpf_get_current_pid_tgid() stores the TGID in the upper 32 bits.
   * Linux TGIDs are positive pid_t values, and pid_t is a signed int,
   * so every valid TGID is representable by this return type.
   */
  return (int)(u32)(bpf_get_current_pid_tgid() >> 32);
}
