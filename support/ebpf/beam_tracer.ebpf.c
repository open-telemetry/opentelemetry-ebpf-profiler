#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of frames to unwind per frame-unwinding eBPF program.
#define FRAMES_PER_PROGRAM   8

bpf_map_def SEC("maps") beam_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(BEAMProcInfo),
  .max_entries = 1024,
};

static inline __attribute__((__always_inline__))
ErrorCode unwind_one_frame(PerCPURecord *record, BEAMProcInfo *info, bool top) {
  UnwindState *state = &record->state;
  Trace *trace = &record->trace;
  unsigned long regs[2], sp = state->sp, fp = state->fp, pc = state->pc;

  DEBUG_PRINT("beam: pc: %lx, sp: %lx, fp: %lx", pc, sp, fp);

  if (fp) {
    unwinder_mark_nonleaf_frame(state);
  }
  _push_with_return_address(trace, 0xf00d, pc, FRAME_MARKER_BEAM, state->return_address);

  // Data that will be sent to HA is in these variables.
  //uintptr_t pointer_and_type = 0, delta_or_marker = 0;

frame_done:
  // Unwind with frame pointer
  if (bpf_probe_read_user(regs, sizeof(regs), (void*)fp)) {
    DEBUG_PRINT("beam:  --> bad frame pointer");
    return ERR_UNREACHABLE;
  }

  state->sp = fp + sizeof(regs);
  state->fp = regs[0];
  state->pc = regs[1];
  if (state->fp) {
    unwinder_mark_nonleaf_frame(state);
  }

  DEBUG_PRINT("beam: pc: %lx, sp: %lx, fp: %lx",
              (unsigned long) state->pc, (unsigned long) state->sp,
              (unsigned long) state->fp);

  return ERR_OK;
}

SEC("perf_event/unwind_beam")
int unwind_beam(struct pt_regs *ctx) {
  DEBUG_PRINT(">>>>>>>>>>>>>>>>>Unwinding BEAM stack<<<<<<<<<<<<<<<<<");

  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace = &record->trace;
  u32 pid = trace->pid;
  DEBUG_PRINT("==== unwind_beam %d ====", trace->stack_len);

  int unwinder = PROG_UNWIND_STOP;
  ErrorCode error = ERR_OK;
  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);
  if (!info) {
    DEBUG_PRINT("beam: no BEAMProcInfo for this pid");
    goto exit;
  }

#pragma unroll
  for (int i = 0; i < FRAMES_PER_PROGRAM; i++) {
    error = unwind_one_frame(record, info, i == 0);
    if (error) {
      break;
    }

    if (record->state.fp == 0) {
      unwinder = PROG_UNWIND_STOP;
      break;
    }

    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_BEAM) {
      break;
    }
  }

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("beam: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}
