#include "bpfdefs.h"
#include "frametypes.h"
#include "tracemgmt.h"
#include "types.h"

// with_debug_output is set during load time.
BPF_RODATA_VAR(u32, with_debug_output, 0)

// filter_idle_frames is set during load time.
BPF_RODATA_VAR(bool, filter_idle_frames, false)

// inverse_pac_mask is set during load time.
BPF_RODATA_VAR(u64, inverse_pac_mask, 0)

// tpbase_offset is set during load time.
// The offset of the Thread Pointer Base variable in `task_struct`. It is
// populated by the host agent based on kernel code analysis.
BPF_RODATA_VAR(u64, tpbase_offset, 0)

// task_stack_offset is set during load time.
// The offset of stack base within `task_struct`.
BPF_RODATA_VAR(u32, task_stack_offset, 0)

// stack_ptregs_offset is set during load time.
// The offset of struct pt_regs within the kernel entry stack.
BPF_RODATA_VAR(u32, stack_ptregs_offset, 0)

// If enabled, the profiler translates host-level PIDs/TGIDs into the
// corresponding IDs within a specific PID namespace. This is essential
// for sidecar deployments to report PIDs consistent with the container's
// internal view (e.g., reporting PID 1 instead of the host PID).
BPF_RODATA_VAR(bool, pid_ns_translation_enabled, false)

// The inode number of the target PID namespace.
// Obtained by calling stat() on /proc/self/ns/pid.
BPF_RODATA_VAR(u64, target_pid_ns_inode, 0)

// The device ID (st_dev) of the target PID namespace inode.
// Required by the bpf_get_ns_current_pid_tgid helper to uniquely
// identify the namespace filesystem (nsfs) instance.
BPF_RODATA_VAR(u64, target_pid_ns_dev, 0)

// Mirrors the kernel's struct bpf_pidns_info for use with bpf_get_ns_current_pid_tgid().
// pid:  thread PID as seen within the target PID namespace.
// tgid: thread group ID (= process PID in userspace) within the target PID namespace.
struct bpf_pidns_info {
  u32 pid;
  u32 tgid;
};

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given
// fileID.
#define STACK_DELTA_BUCKET(X)                                                                      \
  struct exe_id_to_##X##_stack_deltas_t {                                                          \
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                                                       \
    __type(key, u64);                                                                              \
    __type(value, u32);                                                                            \
    __uint(max_entries, 4096);                                                                     \
    __array(                                                                                       \
      values, struct {                                                                             \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                          \
        __uint(max_entries, 1 << X);                                                               \
        __type(key, u32);                                                                          \
        __type(value, StackDelta);                                                                 \
      });                                                                                          \
  } exe_id_to_##X##_stack_deltas SEC(".maps");

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);
STACK_DELTA_BUCKET(22);
STACK_DELTA_BUCKET(23);

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
struct unwind_info_array_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, UnwindInfo);
  __uint(max_entries, UNWIND_INFO_MAX_ENTRIES);
} unwind_info_array SEC(".maps");

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
struct interpreter_offsets_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, OffsetRange);
  __uint(max_entries, 32);
} interpreter_offsets SEC(".maps");

// Maps fileID and page to information of stack deltas associated with that page.
struct stack_delta_page_to_info_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, StackDeltaPageKey);
  __type(value, StackDeltaPageInfo);
  __uint(max_entries, 40000);
} stack_delta_page_to_info SEC(".maps");

#include "native_stack_trace.h"

// unwind_native is the tail call destination for PROG_UNWIND_NATIVE.
static EBPF_INLINE int unwind_native(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  int unwinder;
  ErrorCode error;
  for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;

    // Unwind native code
    DEBUG_PRINT("==== unwind_native %d ====", trace->num_frames);
    increment_metric(metricID_UnwindNativeAttempts);

    // Push frame first. The PC is valid because a text section mapping was found.
    DEBUG_PRINT(
      "Pushing %llx %llx to position %u on stack",
      record->state.text_section_id,
      record->state.text_section_offset,
      trace->num_frames);
    error = push_native(
      &record->state,
      trace,
      record->state.text_section_id,
      record->state.text_section_offset,
      record->state.return_address);
    if (error) {
      DEBUG_PRINT("failed to push native frame");
      break;
    }

    // Unwind the native frame using stack deltas. Stop if no next frame.
    bool stop;
    error = unwind_one_frame(record, &stop);
    if (error || stop) {
      break;
    }

    // Continue unwinding
    DEBUG_UNWIND_STATE(&record->state);
    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_NATIVE) {
      break;
    }
  }

  // Tail call needed for recursion, switching to interpreter unwinder, or reporting
  // trace due to end-of-trace or error. The unwinder program index is set accordingly.
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in unwind_native", unwinder);
  return -1;
}

SEC("perf_event/native_tracer_entry")
int native_tracer_entry(struct bpf_perf_event_data *ctx)
{
  u32 pid = 0;
  u32 tid = 0;
  if (pid_ns_translation_enabled) {
    struct bpf_pidns_info ns_info = {0};
    long ret                      = bpf_get_ns_current_pid_tgid(
      target_pid_ns_dev, target_pid_ns_inode, &ns_info, sizeof(ns_info));
    if (ret < 0) {
      // Task is not in the target namespace; skip it.
      return 0;
    }
    // ns_info.tgid is the thread group ID (= process PID in userspace) in the namespace.
    // ns_info.pid is the thread PID in the namespace.
    // Match the convention of the non-namespace path where pid holds the TGID.
    pid = ns_info.tgid;
    tid = ns_info.pid;
  } else {
    // bpf_get_current_pid_tgid returns (tgid << 32 | pid).
    u64 id = bpf_get_current_pid_tgid();
    pid    = id >> 32;
    tid    = id & 0xFFFFFFFF;
  }

  if (pid == 0 && filter_idle_frames) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  return collect_trace((struct pt_regs *)&ctx->regs, TRACE_SAMPLING, pid, tid, ts, 0);
}
MULTI_USE_FUNC(unwind_native)
