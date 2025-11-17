#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

struct beam_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, BEAMProcInfo);
  __uint(max_entries, 256);
} beam_procs SEC(".maps");

// unwind_beam is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// BEAM stack frames to the trace object for the current CPU.
static EBPF_INLINE int unwind_beam(struct pt_regs *ctx)
{

  int unwinder    = PROG_UNWIND_STOP;
  ErrorCode error = ERR_OK;

  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    DEBUG_PRINT("beam: no PerCPURecord found");
    return -1;
  }

  Trace *trace       = &record->trace;
  UnwindState *state = &record->state;
  u32 pid            = trace->pid;

  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);

  if (!info) {
    DEBUG_PRINT("beam: no BEAMProcInfo for this pid");
    error = ERR_BEAM_NO_PROC_INFO;
    goto exit;
  }

  unwinder_mark_nonleaf_frame(state);
  _push_with_return_address(trace, 0LL, state->pc, FRAME_MARKER_BEAM, state->return_address);
  // Pretend that there was an error unwinding for now,
  // so that we don't have an infinite loop,
  // since we're not actually unwinding / updating the state.
  error = ERR_BEAM_PC_INVALID;

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("beam: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}

MULTI_USE_FUNC(unwind_beam)