// This file contains the code and map definitions that are shared between
// the tracers, as well as a dispatcher program that can be attached to a
// perf event and will call the appropriate tracer for a given process

#include "bpfdefs.h"
#include "go_runtime.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// Begin shared maps

// Per-CPU record of the stack being built and meta-data on the building process
struct per_cpu_records_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, PerCPURecord);
  __uint(max_entries, 1);
} per_cpu_records SEC(".maps");

// per_cpu_records_kp is a second per-CPU record used by the probe unwinder.
// At load time loadProbeUnwinders repoints its get_per_cpu_record() from
// per_cpu_records to this map, so a perf sampler interrupting an in-flight uprobe
// unwind (uprobes are not covered by bpf_prog_active) cannot clobber its record.
struct per_cpu_records_kp_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, PerCPURecord);
  __uint(max_entries, 1);
} per_cpu_records_kp SEC(".maps");

// metrics maps metric ID to a value
struct metrics_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, metricID_Max);
} metrics SEC(".maps");

// perf_progs maps from a program ID to a perf eBPF program
struct perf_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, NUM_TRACER_PROGS);
} perf_progs SEC(".maps");

// report_events notifies user space about events (GENERIC_PID).
//
// As a key the CPU number is used and the value represents a perf event file descriptor.
// Information transmitted is the event type only. We use 0 as the number of max entries
// for this map as at load time it will be replaced by the number of possible CPUs. At
// the same time this will then also define the number of perf event rings that are
// used for this map.
struct report_events_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, int);
  __type(value, u32);
  __uint(max_entries, 0);
} report_events SEC(".maps");

// reported_pids is a map that holds PIDs recently reported to user space.
//
// We use this map to avoid sending multiple notifications for the same PID to user space.
// As key, we use the PID and value is a rate limit token (see pid_event_ratelimit()).
// When sizing this map, we are thinking about the maximum number of unique PIDs that could
// be stored, without immediately being removed, that we would like to support. PIDs are
// either left to expire from the LRU or updated based on the rate limit token. Note that
// timeout checks are done lazily on access, so this map may contain multiple expired PIDs.
struct reported_pids_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 65536);
} reported_pids SEC(".maps");

// pid_events is a map that holds PIDs that should be processed in user space.
//
// User space code will periodically iterate through the map and process each entry.
// Additionally, each time eBPF code writes a value into the map, user space is notified
// through event_send_trigger (which uses maps/report_events). As key we use the PID/TID
// of the process/thread and as value always true. When sizing this map, we are thinking
// about the maximum number of unique PIDs that could generate events we're interested in
// (process new, thread group exit, unknown PC) within a map monitor/processing interval,
// that we would like to support.
struct pid_events_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, bool);
  __uint(max_entries, 65536);
} pid_events SEC(".maps");

// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
struct pid_page_to_mapping_info_t {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, PIDPage);
  __type(value, PIDPageMappingInfo);
  __uint(max_entries, 524288); // 2^19
  __uint(map_flags, BPF_F_NO_PREALLOC);
} pid_page_to_mapping_info SEC(".maps");

// inhibit_events map is used to inhibit sending events to user space.
//
// Only one event needs to be sent as it's a manual trigger to start processing
// traces / PIDs early. HA (Go) will reset this entry once it has reacted to the
// trigger, so next event is sent when needed.
// NOTE: Update .max_entries if additional event types are added. The value should
// equal the number of different event types using this mechanism.
struct inhibit_events_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, bool);
  __uint(max_entries, 2);
} inhibit_events SEC(".maps");

// Ring buffer for sending completed traces to userspace.
//
// The map is periodically polled and read from in `tracer`.
// NOTE: We use 0 as the number of max entries for this map as at load time
// it will be adjusted based on the number of possible CPUs, sampling rate and
// other factors.
struct trace_events_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 0);
} trace_events SEC(".maps");

// End shared maps

// Implements the specification to share span/trace IDs according to:
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/trace-profile-correlation.md
struct traces_ctx_v1_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, SpanTraceInfo);
  __uint(max_entries, 1 << 14);
} traces_ctx_v1 SEC(".maps");

struct thread_context_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, ThreadContextProcInfo);
  __uint(max_entries, 1024);
} thread_context_procs SEC(".maps");

// go_procs stores Go runtime-specific offsets per Go process.
struct go_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, GoRuntimeOffsets);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

// filter_error_frames is set during load time.
BPF_RODATA_VAR(bool, filter_error_frames, false)

// go_labels_disabled gates Go label extraction. It mirrors the Go labels
// configuration (Config.IsLabelsDisabled). The Go runtime offsets are loaded
// independently whenever Go support is enabled.
BPF_RODATA_VAR(bool, go_labels_disabled, true)

// Implements the specification to share span/trace IDs according to:
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/trace-profile-correlation.md
static EBPF_INLINE void maybe_add_otel_span_trace_id(Trace *trace)
{
  u64 id = bpf_get_current_pid_tgid();

  SpanTraceInfo *info = bpf_map_lookup_elem(&traces_ctx_v1, &id);
  if (!info) {
    return;
  }

  trace->trace_id = info->trace_id;
  trace->span_id  = info->span_id;
}

// Stub: only looks the process up, so thread_context_procs stays loaded
// regardless of whether the tracer is enabled. Reading and decoding the
// thread context lands in a later change.
static EBPF_INLINE void maybe_add_thread_context_info(Trace *trace)
{
  u32 pid                     = trace->pid;
  ThreadContextProcInfo *proc = bpf_map_lookup_elem(&thread_context_procs, &pid);
  if (!proc) {
    return;
  }
}

// Golang label extraction
static EBPF_INLINE bool golabel_push(Trace *trace, struct GoString *k, struct GoString *v)
{
  GolangLabel *l = reserve_variable_data(trace, sizeof(GolangLabel), 0);
  if (!l) {
    return false;
  }

  volatile u8 klen = MIN(k->len, sizeof l->key - 1);
  if (bpf_probe_read_user(l->key, klen, k->str)) {
    DEBUG_PRINT("cl: failed to read label key (%lx)", (unsigned long)k->str);
    return false;
  }
  l->key[klen] = 0;

  volatile u8 vlen = MIN(v->len, sizeof l->val - 1);
  if (bpf_probe_read_user(l->val, vlen, v->str)) {
    DEBUG_PRINT("cl: failed to read label value (%lx)", (unsigned long)v->str);
    return false;
  }
  l->val[vlen] = 0;
  commit_variable_data(trace, sizeof(GolangLabel));

  return true;
}

static EBPF_INLINE bool go_labels_get_from_slice(PerCPURecord *record, void *labels_slice_ptr)
{
  // https://github.com/golang/go/blob/80e2e474/src/runtime/pprof/label.go#L20
  struct GoSlice labels_slice;
  if (bpf_probe_read_user(&labels_slice, sizeof(struct GoSlice), labels_slice_ptr)) {
    DEBUG_PRINT("cl: failed to read value for labels slice (%lx)", (unsigned long)labels_slice_ptr);
    return false;
  }

  // len is number of pairs, ie its a vector of key/val structs.
  u64 num = 2 * (u64)MIN(labels_slice.len, MAX_GO_LABELS);
  if (bpf_probe_read_user(
        &record->goLabels, sizeof(struct GoString) * (u32)num, labels_slice.array)) {
    DEBUG_PRINT(
      "cl: failed to read strings from labels slice (%lx)", (unsigned long)labels_slice.array);
    return false;
  }

  // Convert the data from the scratch array to event label data payload
  bool ret = false;
  for (u64 i = 0; i < 2 * MAX_GO_LABELS; i += 2) {
    if (i >= num)
      break;
    if (!golabel_push(&record->trace, &record->goLabels[i], &record->goLabels[i + 1]))
      goto done;
  }
  ret = true;
done:
  return ret;
}

static EBPF_INLINE bool go_labels_get_from_map(PerCPURecord *record, void *labels_map_ptr_ptr)
{
  GoRuntimeOffsets *offs = &record->goOffsets;
  void *labels_map_ptr;
  if (bpf_probe_read_user(&labels_map_ptr, sizeof(labels_map_ptr), labels_map_ptr_ptr)) {
    DEBUG_PRINT(
      "cl: failed to read value for labels_map_ptr (%lx)", (unsigned long)labels_map_ptr_ptr);
    return false;
  }

  u64 labels_count = 0;
  if (bpf_probe_read_user(&labels_count, sizeof(labels_count), labels_map_ptr + offs->hmap_count)) {
    DEBUG_PRINT("cl: failed to read value for labels_count");
    return false;
  }
  if (labels_count == 0) {
    DEBUG_PRINT("cl: no labels");
    return true;
  }

  unsigned char log_2_bucket_count;
  if (bpf_probe_read_user(
        &log_2_bucket_count,
        sizeof(log_2_bucket_count),
        labels_map_ptr + offs->hmap_log2_bucket_count)) {
    DEBUG_PRINT("cl: failed to read value for bucket_count");
    return false;
  }
  GoMapBucket *label_buckets;
  if (bpf_probe_read_user(
        &label_buckets, sizeof(label_buckets), labels_map_ptr + offs->hmap_buckets)) {
    DEBUG_PRINT("cl: failed to read value for label_buckets");
    return false;
  }

  // Limit extracted labels to MAX_GO_LABELS
  const u16 max_end = record->trace.variable_data_end + MAX_GO_LABEL_DATA_SZ;

  // If the map has more than 16 buckets we just don't support it, pprof maps are typically
  // small and if its a problem upgrading to Go 1.24+ is a potential solution.
  u64 bucket_count = 1UL << log_2_bucket_count;
  bool ret         = false;
  for (u64 b = 0; b < 16; b++) {
    if (b >= bucket_count)
      break;

    GoMapBucket *bucket = &record->goMapBucket;
    if (bpf_probe_read_user(bucket, sizeof(GoMapBucket), &label_buckets[b])) {
      goto done;
    }

    for (u64 i = 0; i < GO_MAP_BUCKET_SIZE; i++) {
      // map tophash values for Go 1.12 (first supported) to 1.23 (last used in pprof)
      // https://github.com/golang/go/blob/6885bad7dd/src/runtime/map.go#L82-L87
      const u8 emptyRest = 0, minTopHash = 5;

      u8 tophash = bucket->tophash[i];
      if (tophash == emptyRest)
        break;
      if (tophash < minTopHash)
        continue;
      if (!golabel_push(&record->trace, &bucket->keys[i], &bucket->values[i]))
        goto done;
      if (record->trace.variable_data_end >= max_end)
        goto success;
    }
  }
success:
  ret = true;
done:
  return ret;
}

// Go processes store the current goroutine in thread local store. From there
// this reads the g (aka goroutine) struct, then the m (the actual operating
// system thread) of that goroutine, and finally curg (current goroutine). This
// chain is necessary because getg().m.curg points to the current user g
// assigned to the thread (curg == getg() when not on the system stack). curg
// may be nil if there is no user g, such as when running in the scheduler. If
// curg is nil, then g is either a system stack (called g0) or a signal handler
// g (gsignal). Neither one will ever have label.
static EBPF_INLINE bool add_golang_labels(PerCPURecord *record, void *m_ptr)
{
  GoRuntimeOffsets *offs = &record->goOffsets;
  size_t curg_ptr_addr;
  if (bpf_probe_read_user(&curg_ptr_addr, sizeof(void *), m_ptr + offs->curg)) {
    DEBUG_PRINT("cl: failed to read value for m_ptr->curg");
    return false;
  }

  void *labels_ptr;
  if (bpf_probe_read_user(&labels_ptr, sizeof(void *), (void *)(curg_ptr_addr + offs->labels))) {
    DEBUG_PRINT(
      "cl: failed to read value for curg->labels (%lx->%lx)",
      (unsigned long)curg_ptr_addr,
      (unsigned long)offs->labels);
    return false;
  }

  if (offs->hmap_buckets == 0) {
    // go 1.24+ labels is a slice
    return go_labels_get_from_slice(record, labels_ptr);
  }
  // go 1.23- labels is a map
  return go_labels_get_from_map(record, labels_ptr);
}

static EBPF_INLINE void maybe_add_golang_labels(PerCPURecord *record)
{
  if (go_labels_disabled) {
    return;
  }

  GoRuntimeOffsets *offsets = &record->goOffsets;
  if (offsets->m_offset == 0) {
    DEBUG_PRINT("cl: %d not a go binary", record->trace.pid);
    return;
  }

  void *m_ptr = go_get_m_ptr(offsets, &record->state);
  if (!m_ptr) {
    return;
  }

  DEBUG_PRINT("cl: collecting Go labels");
  increment_metric(metricID_UnwindGoLabelsAttempts);
  if (!add_golang_labels(record, m_ptr)) {
    increment_metric(metricID_UnwindGoLabelsFailures);
  }
  record->trace.golang_label_end = end_variable_data(&record->trace, sizeof(GolangLabel));
}

// unwind_stop is the tail call destination for PROG_UNWIND_STOP.
static EBPF_INLINE int unwind_stop(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;
  Trace *trace       = &record->trace;
  UnwindState *state = &record->state;

  maybe_add_otel_span_trace_id(trace);

  // If the stack is otherwise empty, push an error for that: we should
  // never encounter empty stacks for successful unwinding.
  if (trace->num_frames == 0 && trace->kernel_frame_end == 0) {
    DEBUG_PRINT("unwind_stop called but the stack is empty");
    increment_metric(metricID_ErrEmptyStack);
    if (!state->unwind_error) {
      state->unwind_error = ERR_EMPTY_STACK;
    }
  }

  refine_missing_mapping_error(state, record->usesAnonymousMappings);

  // If unwinding was aborted due to a critical error, push an error frame.
  if (state->unwind_error) {
    DEBUG_PRINT("Aborting further unwinding due to error code %d", state->unwind_error);
    push_abort(trace, state->unwind_error);
  }

  switch (state->error_metric) {
  case -1:
    // No Error
    break;
  case metricID_UnwindNativeErrWrongTextSection:;
    u64 pid_tgid = (u64)trace->pid << 32 | trace->tid;
    if (report_pid(ctx, pid_tgid, record->ratelimitAction)) {
      increment_metric(metricID_NumUnknownPC);
    }
    // fallthrough
  default: increment_metric((u32)state->error_metric);
  }

  // TEMPORARY HACK
  //
  // If we ended up with a trace that consists of only a single error frame, drop it.
  // This is required as long as the process manager provides the option to filter out
  // error frames, to prevent empty traces from being sent. While it might seem that this
  // filtering should belong into the HA code that does the filtering, it is actually
  // surprisingly hard to implement that way: since traces and their counts are reported
  // through different data structures, we'd have to keep a list of known empty traces to
  // also prevent the corresponding trace counts to be sent out. OTOH, if we do it here,
  // this is trivial.
  if (filter_error_frames) {
    if (trace->num_frames == 1 && trace->kernel_frame_end == 0 && state->unwind_error) {
      return 0;
    }
  }
  // TEMPORARY HACK END

  trace->frame_data_end = end_variable_data(trace, sizeof(u64));

  maybe_add_thread_context_info(trace);
  maybe_add_golang_labels(record);
  send_trace(ctx, trace);

  return 0;
}
MULTI_USE_FUNC(unwind_stop)

char _license[] SEC("license") = "GPL";
