#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of frames to unwind per frame-unwinding eBPF program.
#define FRAMES_PER_PROGRAM   16

bpf_map_def SEC("maps") beam_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(BEAMProcInfo),
  .max_entries = 256,
};

static EBPF_INLINE ErrorCode unwind_one_beam_frame(PerCPURecord *record, u64 active_ranges) {
  UnwindState *state = &record->state;
  Trace *trace = &record->trace;
  u64 sp = state->sp, fp = state->fp, pc = state->pc;

  DEBUG_PRINT("beam: pc: %llx, sp: %llx, fp: %llx", pc, sp, fp);

  bpf_probe_read_user(&state->fp, sizeof(u64), (void*)fp);
  bpf_probe_read_user(&state->pc, sizeof(u64), (void*)(fp+8));
  bpf_probe_read_user(&state->sp, sizeof(u64), (void*)(fp+16));

  unwinder_mark_nonleaf_frame(state);

  _push_with_return_address(trace, active_ranges, pc, FRAME_MARKER_BEAM, state->return_address);

  return ERR_OK;
}

// unwind_beam is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// BEAM stack frames to the trace object for the current CPU.
static EBPF_INLINE int unwind_beam(struct pt_regs *ctx) {
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

	// "the_active_code_index" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
  u32 the_active_code_index;
  bpf_probe_read_user(&the_active_code_index, sizeof(u32), (void*)info->the_active_code_index);

	// Index into the active static `r` variable using the currently-active code index
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
  u64 active_ranges = info->r + (the_active_code_index * info->ranges_sizeof);
  DEBUG_PRINT("==== unwind_beam active_ranges: %llx, the_active_code_index: %d ====", active_ranges, the_active_code_index);

#pragma unroll
  for (int i = 0; i < FRAMES_PER_PROGRAM; i++) {
    if (record->state.fp & 0x3) {
      unwinder = PROG_UNWIND_NATIVE;
      break;
    }

    error = unwind_one_beam_frame(record, active_ranges);
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