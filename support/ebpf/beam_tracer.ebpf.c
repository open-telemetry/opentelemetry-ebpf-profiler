#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of frames to unwind per frame-unwinding eBPF program.
#define FRAMES_PER_PROGRAM 8

// The max number of loops to unroll when searching for the correct CodeHeader.
// Should be log base 2 of a reasonable number of modules to binary-search through.
#define CODE_HEADER_SEARCH_ITERATIONS 16

// The max number of loops to unroll when scanning the stack from for continuation pointers
#define STACK_FRAME_SCAN_ITERATIONS 16

#if defined(__x86_64__)
  #define SP_REGISTER sp
#elif defined(__aarch64__)
  // Native stack is not supported on ARM due to 16-byte stack alignment hassle
  #define SP_REGISTER r20
#endif

struct beam_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, BEAMProcInfo);
  __uint(max_entries, 256);
} beam_procs SEC(".maps");

typedef struct BEAMRangeEntry {
  u64 start;
  u64 end;
} BEAMRangeEntry;

typedef struct BEAMRangesInfo {
  u64 modules;
  u64 n;
  BEAMRangeEntry first, mid, last;
} BEAMRangesInfo;

static EBPF_INLINE ErrorCode
unwind_one_beam_frame(PerCPURecord *record, BEAMRangesInfo *ranges, bool frame_pointers_enabled)
{
  UnwindState *state = &record->state;
  Trace *trace       = &record->trace;
  u64 pc             = state->pc;

  if (pc < ranges->first.start || pc > ranges->last.end) {
    return ERR_BEAM_PC_INVALID;
  }

  u64 low     = 0;
  u64 high    = ranges->n;
  u64 current = low + (high - low) / 2;

  BEAMRangeEntry current_range;
  current_range.start = ranges->mid.start;
  current_range.end   = ranges->mid.end;

  UNROLL for (int i = 0; i < CODE_HEADER_SEARCH_ITERATIONS; i++)
  {
    if (pc < current_range.start) {
      high = current;
    } else if (pc >= current_range.end) {
      low = current + 1;
    } else {
      // `pc` is in the `current_range` CodeHeader
      _push_with_return_address(
        trace, current_range.start, pc, FRAME_MARKER_BEAM, state->return_address);
      break;
    }

    current  = low + (high - low) / 2;
    u64 addr = ranges->modules + current * sizeof(BEAMRangeEntry);
    if (bpf_probe_read_user((void *)&current_range, sizeof(BEAMRangeEntry), (void *)(addr))) {
      DEBUG_PRINT("beam: Failed to read ranges[%llu]", current);
      return ERR_BEAM_MODULES_READ_FAILURE;
    }
  }

  if (frame_pointers_enabled) {
    if (!unwinder_unwind_frame_pointer(state)) {
      DEBUG_PRINT("beam: invalid frame pointer");
      return ERR_BEAM_FRAME_POINTER_INVALID;
    }
  } else {
    UNROLL for (int i = 0; i < STACK_FRAME_SCAN_ITERATIONS; i++)
    {
      state->SP_REGISTER += 8;
      bpf_probe_read_user(&state->pc, sizeof(u64), (void *)state->SP_REGISTER);
      if ((state->pc & 0x03) == 0) {
        break;
      }
    }

    if ((state->pc & 0x03) != 0) {
      return ERR_BEAM_STACK_SCAN_EXHAUSTED;
    }
  }

  return ERR_OK;
}

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

  // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_vm.h#L68-L73
  bool frame_pointers_enabled = info->erts_frame_layout == 1;

  DEBUG_PRINT(
    "==== unwind_beam %d (frame_pointers: %d)====", trace->stack_len, frame_pointers_enabled);

  // "the_active_code_index" symbol is from:
  // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
  u32 the_active_code_index;
  if (bpf_probe_read_user(
        &the_active_code_index, sizeof(u32), (void *)info->the_active_code_index)) {
    DEBUG_PRINT("beam: Failed to read the_active_code_index");
    error = ERR_BEAM_ACTIVE_CODE_INDEX_READ_FAILURE;
    goto exit;
  }

  // Index into the active static `r` variable using the currently-active code index
  // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
  u64 active_ranges = info->r + (the_active_code_index * info->ranges_sizeof);

  DEBUG_PRINT(
    "beam: r: %llx, the_active_code_index: %d, active_ranges: %llx",
    info->r,
    the_active_code_index,
    active_ranges);

  BEAMRangesInfo ranges;

  if (bpf_probe_read_user(
        &ranges.modules, sizeof(u64), (void *)(active_ranges + info->ranges_modules))) {
    DEBUG_PRINT("beam: Failed to read ranges.modules");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  if (bpf_probe_read_user(&ranges.n, sizeof(u64), (void *)(active_ranges + info->ranges_n))) {
    DEBUG_PRINT("beam: Failed to read ranges.n");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT("beam: modules: %llx, n: %llu", ranges.modules, ranges.n);

  if (bpf_probe_read_user(&ranges.first, sizeof(BEAMRangeEntry), (void *)(ranges.modules))) {
    DEBUG_PRINT("beam: Failed to read ranges.first");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }
  if (bpf_probe_read_user(
        &ranges.mid,
        sizeof(BEAMRangeEntry),
        (void *)(ranges.modules + (ranges.n / 2) * sizeof(BEAMRangeEntry)))) {
    DEBUG_PRINT("beam: Failed to read ranges.mid");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }
  if (bpf_probe_read_user(
        &ranges.last,
        sizeof(BEAMRangeEntry),
        (void *)(ranges.modules + (ranges.n - 1) * sizeof(BEAMRangeEntry)))) {
    DEBUG_PRINT("beam: Failed to read ranges.last");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT(
    "beam: ranges.first.start: %llx, ranges.last.end: %llx", ranges.first.start, ranges.last.end);

  UNROLL for (int i = 0; i < FRAMES_PER_PROGRAM; i++)
  {
    unwinder_mark_nonleaf_frame(state);
    if (record->state.pc == info->beam_normal_exit) {
      unwinder = PROG_UNWIND_STOP;
      break;
    }

    error = unwind_one_beam_frame(record, &ranges, frame_pointers_enabled);
    if (error) {
      break;
    }

    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_BEAM) {
      break;
    }
  }

exit:
  state->unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("beam: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}

MULTI_USE_FUNC(unwind_beam)