#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of frames to unwind per frame-unwinding eBPF program.
#define BEAM_FRAMES_PER_PROGRAM 8

// The max number of loops to unroll when searching for the correct CodeHeader.
// Should be log base 2 of a reasonable number of modules to binary-search through.
#define BEAM_CODE_HEADER_SEARCH_ITERATIONS 16

// The max number of loops to unroll when scanning the stack from for continuation pointers
#define BEAM_STACK_FRAME_SCAN_ITERATIONS 16

struct beam_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, BEAMProcInfo);
  __uint(max_entries, 256);
} beam_procs SEC(".maps");

// We assume this Range struct is stable so we can read it all at once directly.
// If it were to change in the future, we'd need to change the way this struct is read.
// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L31-L34
typedef struct BEAMRangeEntry {
  u64 start;
  u64 end;
} BEAMRangeEntry;

// We assume this ranges struct will at least have these two values as the first two fields.
// That allows us to directly read them efficiently at once, but it could break in in the future.
// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
typedef struct BEAMRangesInfo {
  u64 modules;
  u64 n;
} BEAMRangesInfo;

typedef struct BEAMRangesSearchCache {
  BEAMRangesInfo info;
  BEAMRangeEntry first, mid, last;
} BEAMRangesSearchCache;

static EBPF_INLINE ErrorCode push_beam(UnwindState *state, Trace *trace, u64 range_start)
{
  const u8 ra_flag = state->return_address ? FRAME_FLAG_RETURN_ADDRESS : 0;

  // `pc` is in the `current_range` CodeHeader
  u64 *data = push_frame(state, trace, FRAME_MARKER_BEAM, ra_flag, state->pc, 1);
  if (!data) {
    return false;
  }
  data[0] = range_start;
  return true;
}

static EBPF_INLINE ErrorCode
unwind_one_beam_frame(PerCPURecord *record, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  UnwindState *state = &record->state;
  Trace *trace       = &record->trace;
  u64 pc             = state->pc;

  if (pc < ranges->first.start || pc > ranges->last.end) {
    return ERR_BEAM_PC_INVALID;
  }

  u64 low     = 0;
  u64 high    = ranges->info.n;
  u64 current = low + (high - low) / 2;

  BEAMRangeEntry current_range = ranges->mid;

  UNROLL for (int i = 0; i < BEAM_CODE_HEADER_SEARCH_ITERATIONS; i++)
  {
    if (pc < current_range.start) {
      high = current;
    } else if (pc >= current_range.end) {
      low = current + 1;
    } else {
      break;
    }

    current = low + (high - low) / 2;

    u64 entry_ptr = ranges->info.modules + current * sizeof(BEAMRangeEntry);
    if (bpf_probe_read_user(&current_range, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
      DEBUG_PRINT("beam: Failed to read current range");
      return ERR_BEAM_MODULES_READ_FAILURE;
    }
  }

  if (pc < current_range.start || pc >= current_range.end) {
    // Ran out of loop iterations without locating the correct range
    return ERR_BEAM_RANGE_SEARCH_EXHAUSTED;
  }

  if (!push_beam(state, trace, current_range.start)) {
    return ERR_STACK_LENGTH_EXCEEDED;
  }

  if (info->frame_pointers_enabled) {
    if (!unwinder_unwind_frame_pointer(state)) {
      DEBUG_PRINT("beam: invalid frame pointer");
      return ERR_BEAM_FRAME_POINTER_INVALID;
    }
  } else {
    UNROLL for (int i = 0; i < BEAM_STACK_FRAME_SCAN_ITERATIONS; i++)
    {
      // Native stack is not supported on ARM due to 16-byte stack alignment hassle
      // r20 is used to store the stack pointer for JIT code to allow 8-bit alignment.
#if defined(__aarch64__)
      state->r20 += 8;
      bpf_probe_read_user(&state->pc, sizeof(state->pc), (void *)state->r20);
#else
      state->sp += 8;
      bpf_probe_read_user(&state->pc, sizeof(state->pc), (void *)state->sp);
#endif
      // On the stack, if the value is tagged as a header value, then that means it's actually a
      // continuation pointer.
      // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L132
      // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L133
      if ((state->pc & 0x03) == 0) {
        unwinder_mark_nonleaf_frame(state);
        break;
      }
    }

    // If we got here but the pc doesn't look like a continuation pointer, then it means we ran out
    // of loop unroll iterations.
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

  DEBUG_PRINT("==== unwind_beam %d, pc: 0x%llx ====", trace->num_frames, state->pc);

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

  BEAMRangesSearchCache ranges;

  if (bpf_probe_read_user(&ranges.info, sizeof(BEAMRangesInfo), (void *)(active_ranges))) {
    DEBUG_PRINT("beam: Failed to read active ranges");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT("beam: modules: %llx, n: %llu", ranges.info.modules, ranges.info.n);

  u64 entry_ptr = ranges.info.modules;
  if (bpf_probe_read_user(&ranges.first, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read first range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  entry_ptr = ranges.info.modules + (ranges.info.n / 2) * sizeof(BEAMRangeEntry);
  if (bpf_probe_read_user(&ranges.mid, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read middle range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  entry_ptr = ranges.info.modules + (ranges.info.n - 1) * sizeof(BEAMRangeEntry);
  if (bpf_probe_read_user(&ranges.last, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read last range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT("beam: valid addresses 0x%llx - 0x%llx", ranges.first.start, ranges.last.end);

  UNROLL for (int i = 0; i < BEAM_FRAMES_PER_PROGRAM; i++)
  {
    if (record->state.pc == info->beam_normal_exit) {
      unwinder = PROG_UNWIND_STOP;
      break;
    }

    error = unwind_one_beam_frame(record, info, &ranges);
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
