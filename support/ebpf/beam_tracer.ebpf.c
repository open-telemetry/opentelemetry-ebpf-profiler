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
ErrorCode unwind_one_beam_frame(PerCPURecord *record, BEAMProcInfo *info, bool top) {
  UnwindState *state = &record->state;
  Trace *trace = &record->trace;
  u64 sp = state->sp, fp = state->fp, pc = state->pc;

  DEBUG_PRINT("beam: pc: %llx, sp: %llx, fp: %llx", pc, sp, fp);
  DEBUG_PRINT("beam: c_p(r13): %llx", state->r13);

  bpf_probe_read_user(&state->fp, sizeof(u64), (void*)fp);
  bpf_probe_read_user(&state->pc, sizeof(u64), (void*)(fp+8));
  bpf_probe_read_user(&state->sp, sizeof(u64), (void*)(fp+16));

  if (fp && sp) {
    unwinder_mark_nonleaf_frame(state);
  }
  _push_with_return_address(trace, 0xf00d, pc, FRAME_MARKER_BEAM, state->return_address);

  // Data that will be sent to HA is in these variables.
  //uintptr_t pointer_and_type = 0, delta_or_marker = 0;

frame_done:
  // Unwind with frame pointer
  // if (fp & 0x3 || bpf_probe_read_user(regs, sizeof(regs), (void*)fp)) {
  //   DEBUG_PRINT("beam:  --> bad frame pointer");
  //   return ERR_UNREACHABLE;
  // }

  // state->sp = fp - 2 * sizeof(void*);
  // state->fp = regs[1];
  // state->pc = regs[0];
  if (state->fp) {
    unwinder_mark_nonleaf_frame(state);
  }

  DEBUG_PRINT("beam: pc: %llx, sp: %llx, fp: %llx",
              state->pc, state->sp,
              state->fp);

  return ERR_OK;
}

// unwind_beam is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// BEAM stack frames to the trace object for the current CPU.
static inline __attribute__((__always_inline__)) int unwind_beam(struct pt_regs *ctx) {
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
    if (record->state.fp & 0x3) {
      unwinder = PROG_UNWIND_NATIVE;
      break;
    }

    error = unwind_one_beam_frame(record, info, i == 0);
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

MULTI_USE_FUNC(unwind_beam)