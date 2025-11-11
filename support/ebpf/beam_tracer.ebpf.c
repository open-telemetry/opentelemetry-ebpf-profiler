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
static EBPF_INLINE int unwind_beam(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    DEBUG_PRINT("beam: no PerCPURecord found");
    return -1;
  }

  Trace *trace = &record->trace;
  UnwindState *state = &record->state;
  u32 pid = trace->pid;

  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);

  if (!info) {
    DEBUG_PRINT("beam: no BEAMProcInfo for this pid");
    return -1;
  }

  int unwinder = PROG_UNWIND_STOP;
  unwinder_mark_nonleaf_frame(state);
  _push_with_return_address(trace, 0LL, state->pc, FRAME_MARKER_BEAM, state->return_address);

exit:
  record->state.unwind_error = ERR_BEAM_PC_INVALID;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("beam: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}

MULTI_USE_FUNC(unwind_beam)