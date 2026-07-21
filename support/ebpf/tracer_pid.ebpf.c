#include "bpfdefs.h"

SEC("socket") int store_tracer_pid(UNUSED void *ctx)
{
  /* bpf_get_current_pid_tgid() stores the TGID in the upper 32 bits.
   * Linux TGIDs are positive pid_t values, and pid_t is a signed int,
   * so every valid TGID is representable by this return type.
   */
  return (int)(u32)(bpf_get_current_pid_tgid() >> 32);
}
