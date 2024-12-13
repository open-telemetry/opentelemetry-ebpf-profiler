// Provides functionality for adding frames to traces, hashing traces and
// updating trace counts

#ifndef OPTI_TRACEMGMT_H
#define OPTI_TRACEMGMT_H

#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "types.h"
#include "errors.h"

// increment_metric increments the value of the given metricID by 1
static inline __attribute__((__always_inline__))
void increment_metric(u32 metricID) {
  u64 *count = bpf_map_lookup_elem(&metrics, &metricID);
  if (count) {
    ++*count;
  } else {
    DEBUG_PRINT("Failed to lookup metrics map for metricID %d", metricID);
  }
}

// Send immediate notifications for event triggers to Go.
// Notifications for GENERIC_PID and TRACES_FOR_SYMBOLIZATION will be
// automatically inhibited until HA resets the type.
static inline void event_send_trigger(struct pt_regs *ctx, u32 event_type) {
  int inhibit_key = event_type;
  bool inhibit_value = true;

  // GENERIC_PID is a global notification that triggers eBPF map iteration+processing in Go.
  // To avoid redundant notifications while userspace processing for them is already taking
  // place, we allow latch-like inhibition, where eBPF sets it and Go has to manually reset
  // it, before new notifications are triggered.
  if (event_type != EVENT_TYPE_GENERIC_PID) {
    return;
  }

  if (bpf_map_update_elem(&inhibit_events, &inhibit_key, &inhibit_value, BPF_NOEXIST) < 0) {
    DEBUG_PRINT("Event type %d inhibited", event_type);
    return;
  }

  switch (event_type) {
  case EVENT_TYPE_GENERIC_PID:
    increment_metric(metricID_NumGenericPID);
    break;
  default:
    // no action
    break;
  }

  Event event = {.event_type = event_type};
  int ret = bpf_perf_event_output(ctx, &report_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  if (ret < 0) {
    DEBUG_PRINT("event_send_trigger failed to send event %d: error %d", event_type, ret);
  }
}

// Forward declaration
struct bpf_perf_event_data;

// pid_information_exists checks if the given pid exists in pid_page_to_mapping_info or not.
static inline __attribute__((__always_inline__))
bool pid_information_exists(void *ctx, int pid) {
  PIDPage key = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid = __constant_cpu_to_be32((u32) pid);
  key.page = 0;

  return bpf_map_lookup_elem(&pid_page_to_mapping_info, &key) != NULL;
}

// Reset the ratelimit cache
#define RATELIMIT_ACTION_RESET   0
// Use default timer
#define RATELIMIT_ACTION_DEFAULT 1
// Set PID to fast timer mode
#define RATELIMIT_ACTION_FAST    2

// pid_event_ratelimit determines if the PID event should be inhibited or not
// based on rate limiting rules.
static inline __attribute__((__always_inline__))
bool pid_event_ratelimit(u32 pid, int ratelimit_action) {
  const u8 default_max_attempts = 8; // 25 seconds
  const u8 fast_max_attempts = 4; // 1.6 seconds
  const u8 fast_timer_flag = 0x10;
  u64 *token_ptr = bpf_map_lookup_elem(&reported_pids, &pid);
  u64 ts = bpf_ktime_get_ns();
  u8 attempt = 0;
  u8 fast_timer = (ratelimit_action == RATELIMIT_ACTION_FAST) ? fast_timer_flag : 0;

  if (ratelimit_action == RATELIMIT_ACTION_RESET) {
    return false;
  }

  if (token_ptr) {
    u64 token = *token_ptr;
    u64 diff_ts = ts - (token & ~0x1fULL);
    attempt = token & 0xf;
    fast_timer |= token & fast_timer_flag;
    // Calculate the limit window size. 100ms << attempt.
    u64 limit_window_ts = (100*1000000ULL) << attempt;

    if (diff_ts < limit_window_ts) {
      // Minimum event interval.
      DEBUG_PRINT("PID %d event limited: too fast", pid);
      return true;
    }
    if (diff_ts < limit_window_ts + (5000*1000000ULL)) {
      // PID event within 5 seconds, increase limit window size if possible
      if (attempt < (fast_timer ? fast_max_attempts : default_max_attempts)) {
        attempt++;
      }
    } else {
      // Silence for at least 5 seconds. Reset back to zero.
      attempt = 0;
    }
  }

  // Create new token:
  // 59 bits - the high bits of timestamp of last event
  //  1 bit  - set if the PID should be in fast timer mode
  //  4 bits - number of bursts left at event time
  DEBUG_PRINT("PID %d event send, attempt=%d", pid, attempt);
  u64 token = (ts & ~0x1fULL) | fast_timer | attempt;

  // Update the map entry. Technically this is not SMP safe, but doing
  // an atomic update would require EBPF atomics. At worst we send an
  // extra sync event and the likelihood for this race is very low, so
  // we can live with this.
  int err = bpf_map_update_elem(&reported_pids, &pid, &token, BPF_ANY);
  if (err != 0) {
    // Should never happen
    DEBUG_PRINT("Failed to report PID %d: %d", pid, err);
    increment_metric(metricID_ReportedPIDsErr);
    return true;
  }

  return false;
}

// report_pid informs userspace about a PID that needs to be processed.
// If inhibit is true, PID will first be checked against maps/reported_pids
// and reporting aborted if PID has been recently reported.
// Returns true if the PID was successfully reported to user space.
static inline __attribute__((__always_inline__))
bool report_pid(void *ctx, int pid, int ratelimit_action) {
  u32 key = (u32) pid;

  if (pid_event_ratelimit(pid, ratelimit_action)) {
    return false;
  }

  bool value = true;
  int errNo = bpf_map_update_elem(&pid_events, &key, &value, BPF_ANY);
  if (errNo != 0) {
    DEBUG_PRINT("Failed to update pid_events with PID %d: %d", pid, errNo);
    increment_metric(metricID_PIDEventsErr);
    return false;
  }
  if (ratelimit_action == RATELIMIT_ACTION_RESET || errNo != 0) {
    bpf_map_delete_elem(&reported_pids, &key);
  }

  // Notify userspace that there is a PID waiting to be processed.
  // At this point, the PID was successfully written to maps/pid_events,
  // therefore there is no need to track success/failure of event_send_trigger
  // and we can simply return success.
  event_send_trigger(ctx, EVENT_TYPE_GENERIC_PID);
  return true;
}

// Return the per-cpu record.
// As each per-cpu array only has 1 entry, we hard-code 0 as the key.
// The return value of get_per_cpu_record() can never be NULL and return value checks only exist
// to pass the verifier. If the implementation of get_per_cpu_record() is changed so that NULL can
// be returned, also add an error metric.
static inline PerCPURecord *get_per_cpu_record(void)
{
  int key0 = 0;
  return bpf_map_lookup_elem(&per_cpu_records, &key0);
}

// Return the per-cpu record initialized with pristine values for state variables.
// The return value of get_pristine_per_cpu_record() can never be NULL and return value checks
// only exist to pass the verifier. If the implementation of get_pristine_per_cpu_record() is changed
// so that NULL can be returned, also add an error metric.
static inline PerCPURecord *get_pristine_per_cpu_record()
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return record;

  record->state.pc = 0;
  record->state.sp = 0;
  record->state.fp = 0;
#if defined(__x86_64__)
  record->state.r13 = 0;
#elif defined(__aarch64__)
  record->state.lr = 0;
  record->state.r22 = 0;
  record->state.lr_invalid = false;
#endif
  record->state.return_address = false;
  record->state.error_metric = -1;
  record->state.unwind_error = ERR_OK;
  record->perlUnwindState.stackinfo = 0;
  record->perlUnwindState.cop = 0;
  record->pythonUnwindState.py_frame = 0;
  record->phpUnwindState.zend_execute_data = 0;
  record->rubyUnwindState.stack_ptr = 0;
  record->rubyUnwindState.last_stack_frame = 0;
  record->unwindersDone = 0;
  record->tailCalls = 0;
  record->ratelimitAction = RATELIMIT_ACTION_DEFAULT;

  Trace *trace = &record->trace;
  trace->kernel_stack_id = -1;
  trace->stack_len = 0;
  trace->pid = 0;
  trace->tid = 0;

  trace->apm_trace_id.as_int.hi = 0;
  trace->apm_trace_id.as_int.lo = 0;
  trace->apm_transaction_id.as_int = 0;

  return record;
}

// unwinder_is_done checks if a given unwinder program is done for the trace
// extraction round.
static inline __attribute__((__always_inline__))
bool unwinder_is_done(const PerCPURecord *record, int unwinder) {
  return (record->unwindersDone & (1U << unwinder)) != 0;
}

// unwinder_mark_done will mask out a given unwinder program so that it will
// not be called again for the same trace. Used when interpreter unwinder has
// extracted all interpreter frames it can extract.
static inline __attribute__((__always_inline__))
void unwinder_mark_done(PerCPURecord *record, int unwinder) {
  record->unwindersDone |= 1U << unwinder;
}

// unwinder_mark_nonleaf_frame marks the current frame as a non-leaf
// frame from the perspective of the user-mode stack.
// That is, frames that are making a syscall (thus the leaf for the user-mode
// stack, though not the leaf for the entire logical stack) *are*
// considered leaf frames in this sense.
//
// On both x86 and aarch64, this means we need to subtract 1 from
// the address during later processing.
//
// Additionally, on aarch64, this means that we will not trust the current value of
// `lr` to be the return address for this frame.
static inline __attribute__((__always_inline__))
void unwinder_mark_nonleaf_frame(UnwindState *state) {
  state->return_address = true;
#if defined(__aarch64__)
  state->lr_invalid = true;
#endif
}

// Push the file ID, line number and frame type into FrameList with a user-defined
// maximum stack size.
//
// NOTE: The line argument is used for a lot of different purposes, depending on
//       the frame type. For example error frames use it to store the error number,
//       and hotspot puts a subtype and BCI indices, amongst other things (see
//       calc_line). This should probably be renamed to something like "frame type
//       specific data".
static inline __attribute__((__always_inline__))
ErrorCode _push_with_max_frames(Trace *trace, u64 file, u64 line, u8 frame_type, u8 return_address, u32 max_frames) {
  if (trace->stack_len >= max_frames) {
    DEBUG_PRINT("unable to push frame: stack is full");
    increment_metric(metricID_UnwindErrStackLengthExceeded);
    return ERR_STACK_LENGTH_EXCEEDED;
  }

#ifdef TESTING_COREDUMP
  // utils/coredump uses CGO to build the eBPF code. This dispatches
  // the frame information directly to helper implemented in ebpfhelpers.go.
  int __push_frame(u64, u64, u64, u8, u8);
  trace->stack_len++;
  return __push_frame(__cgo_ctx->id, file, line, frame_type, return_address);
#else
  trace->frames[trace->stack_len++] = (Frame) {
      .file_id = file,
      .addr_or_line = line,
      .kind = frame_type,
      .return_address = return_address,
  };

  return ERR_OK;
#endif
}

// Push the file ID, line number and frame type into FrameList
static inline __attribute__((__always_inline__))
ErrorCode _push_with_return_address(Trace *trace, u64 file, u64 line, u8 frame_type, bool return_address) {
  return _push_with_max_frames(trace, file, line, frame_type, return_address, MAX_NON_ERROR_FRAME_UNWINDS);
}

// Push the file ID, line number and frame type into FrameList
static inline __attribute__((__always_inline__))
ErrorCode _push(Trace *trace, u64 file, u64 line, u8 frame_type) {
  return _push_with_max_frames(trace, file, line, frame_type, 0, MAX_NON_ERROR_FRAME_UNWINDS);
}

// Push a critical error frame.
static inline __attribute__((__always_inline__))
ErrorCode push_error(Trace *trace, ErrorCode error) {
  return _push_with_max_frames(trace, 0, error, FRAME_MARKER_ABORT, 0, MAX_FRAME_UNWINDS);
}

// Send a trace to user-land via the `trace_events` perf event buffer.
static inline __attribute__((__always_inline__))
void send_trace(void *ctx, Trace *trace) {
  const u64 num_empty_frames = (MAX_FRAME_UNWINDS - trace->stack_len);
  const u64 send_size = sizeof(Trace) - sizeof(Frame) * num_empty_frames;

  if (send_size > sizeof(Trace)) {
    return; // unreachable
  }

  bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, trace, send_size);
}

// is_kernel_address checks if the given address looks like virtual address to kernel memory.
static bool is_kernel_address(u64 addr) {
  return addr & 0xFF00000000000000UL;
}

// resolve_unwind_mapping decodes the current PC's mapping and prepares unwinding information.
// The state text_section_id and text_section_offset are updated accordingly. The unwinding program
// index that should be used is written to the given `unwinder` pointer.
static ErrorCode resolve_unwind_mapping(PerCPURecord *record, int* unwinder) {
  UnwindState *state = &record->state;
  pid_t pid = record->trace.pid;
  u64 pc = state->pc;

  if (is_kernel_address(pc)) {
    // This should not happen as we should only be unwinding usermode stacks.
    // Seeing PC point to a kernel address indicates a bad unwind.
    DEBUG_PRINT("PC value %lx is a kernel address", (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeErrKernelAddress;
    return ERR_NATIVE_UNEXPECTED_KERNEL_ADDRESS;
  }

  if (pc < 0x1000) {
    // The kernel will always return a start address for user space memory mappings that is
    // above the value defined in /proc/sys/vm/mmap_min_addr.
    // As such small PC values happens regularly (e.g. by handling or extracting the
    // PC value incorrectly) we track them but don't proceed with unwinding.
    DEBUG_PRINT("small pc value %lx, ignoring", (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeSmallPC;
    return ERR_NATIVE_SMALL_PC;
  }

  PIDPage key = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid = __constant_cpu_to_be32((u32) pid);
  key.page = __constant_cpu_to_be64(pc);

  // Check if we have the data for this virtual address
  PIDPageMappingInfo* val = bpf_map_lookup_elem(&pid_page_to_mapping_info, &key);
  if (!val) {
    DEBUG_PRINT("Failure to look up interval memory mapping for PC 0x%lx",
                (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeErrWrongTextSection;
    return ERR_NATIVE_NO_PID_PAGE_MAPPING;
  }

  decode_bias_and_unwind_program(val->bias_and_unwind_program, &state->text_section_bias, unwinder);
  state->text_section_id = val->file_id;
  state->text_section_offset = pc - state->text_section_bias;
  DEBUG_PRINT("Text section id for PC %lx is %llx (unwinder %d)",
    (unsigned long) pc, state->text_section_id, *unwinder);
  DEBUG_PRINT("Text section bias is %llx, and offset is %llx",
    state->text_section_bias, state->text_section_offset);

  return ERR_OK;
}

// get_next_interpreter tries to get the next interpreter unwinder from the section id.
// If the section id happens to be within the range of a known interpreter it will
// return the interpreter unwinder otherwise the native unwinder.
static inline int get_next_interpreter(PerCPURecord *record) {
  UnwindState *state = &record->state;
  u64 section_id = state->text_section_id;
  u64 section_offset = state->text_section_offset;
  // Check if the section id happens to be in the interpreter map.
  OffsetRange *range = bpf_map_lookup_elem(&interpreter_offsets, &section_id);
  if (range != 0) {
    if ((section_offset >= range->lower_offset) && (section_offset <= range->upper_offset)) {
      DEBUG_PRINT("interpreter_offsets match %d", range->program_index);
      if (!unwinder_is_done(record, range->program_index)) {
        increment_metric(metricID_UnwindCallInterpreter);
        return range->program_index;
      }
      DEBUG_PRINT("interpreter unwinder done");
    }
  }
  return PROG_UNWIND_NATIVE;
}

// get_next_unwinder_after_native_frame determines the next unwinder program to run
// after a native stack frame has been unwound.
static inline __attribute__((__always_inline__))
ErrorCode get_next_unwinder_after_native_frame(PerCPURecord *record, int *unwinder) {
  UnwindState *state = &record->state;
  *unwinder = PROG_UNWIND_STOP;

  if (state->pc == 0) {
    DEBUG_PRINT("Stopping unwind due to unwind failure (PC == 0)");
    state->error_metric = metricID_UnwindErrZeroPC;
    return ERR_NATIVE_ZERO_PC;
  }

  DEBUG_PRINT("==== Resolve next frame unwinder: frame %d ====", record->trace.stack_len);
  ErrorCode error = resolve_unwind_mapping(record, unwinder);
  if (error) {
    return error;
  }

  if (*unwinder == PROG_UNWIND_NATIVE) {
    *unwinder = get_next_interpreter(record);
  }

  return ERR_OK;
}

// get_next_unwinder_after_interpreter determines the next unwinder program to run
// after an interpreter (non-native) frame sequence has been unwound.
static inline __attribute__((__always_inline__))
int get_next_unwinder_after_interpreter(const PerCPURecord *record) {
  // Since interpreter-only frame decoding is no longer supported, this
  // currently equals to just resuming native unwinding.
  return PROG_UNWIND_NATIVE;
}

// tail_call is a wrapper around bpf_tail_call() and ensures that the number of tail calls is not
// reached while unwinding the stack.
static inline __attribute__((__always_inline__))
void tail_call(void *ctx, int next) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    bpf_tail_call(ctx, &progs, PROG_UNWIND_STOP);
    // In theory bpf_tail_call() should never return. But due to instruction reordering by the
    // compiler we have to place return here to bribe the verifier to accept this.
    return;
  }

  if (record->tailCalls >= 29 ) {
    // The maximum tail call count we need to support on older kernels is 32. At this point
    // there is a chance that continuing unwinding the stack would further increase the number of
    // tail calls. As a result we might lose the unwound stack as no further tail calls are left
    // to report it to user space. To make sure we do not run into this issue we stop unwinding
    // the stack at this point and report it to userspace.
    next = PROG_UNWIND_STOP;
    record->state.unwind_error = ERR_MAX_TAIL_CALLS;
    increment_metric(metricID_MaxTailCalls);
  }
  record->tailCalls += 1 ;

  bpf_tail_call(ctx, &progs, next);
}

#endif
