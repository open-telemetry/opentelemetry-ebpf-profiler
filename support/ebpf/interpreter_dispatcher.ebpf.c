// This file contains the code and map definitions that are shared between
// the tracers, as well as a dispatcher program that can be attached to a
// perf event and will call the appropriate tracer for a given process

#include "bpfdefs.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"
#include "util.h"

// Begin shared maps

// Per-CPU record of the stack being built and meta-data on the building process
bpf_map_def SEC("maps") per_cpu_records = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(int),
  .value_size  = sizeof(PerCPURecord),
  .max_entries = 1,
};

// metrics maps metric ID to a value
bpf_map_def SEC("maps") metrics = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = metricID_Max,
};

// perf_progs maps from a program ID to a perf eBPF program
bpf_map_def SEC("maps") perf_progs = {
  .type        = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// report_events notifies user space about events (GENERIC_PID and TRACES_FOR_SYMBOLIZATION).
//
// As a key the CPU number is used and the value represents a perf event file descriptor.
// Information transmitted is the event type only. We use 0 as the number of max entries
// for this map as at load time it will be replaced by the number of possible CPUs. At
// the same time this will then also define the number of perf event rings that are
// used for this map.
bpf_map_def SEC("maps") report_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(int),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// reported_pids is a map that holds PIDs recently reported to user space.
//
// We use this map to avoid sending multiple notifications for the same PID to user space.
// As key, we use the PID and value is a rate limit token (see pid_event_ratelimit()).
// When sizing this map, we are thinking about the maximum number of unique PIDs that could
// be stored, without immediately being removed, that we would like to support. PIDs are
// either left to expire from the LRU or updated based on the rate limit token. Note that
// timeout checks are done lazily on access, so this map may contain multiple expired PIDs.
bpf_map_def SEC("maps") reported_pids = {
  .type        = BPF_MAP_TYPE_LRU_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 65536,
};

// pid_events is a map that holds PIDs that should be processed in user space.
//
// User space code will periodically iterate through the map and process each entry.
// Additionally, each time eBPF code writes a value into the map, user space is notified
// through event_send_trigger (which uses maps/report_events). As key we use the PID of
// the process and as value always true. When sizing this map, we are thinking about
// the maximum number of unique PIDs that could generate events we're interested in
// (process new, process exit, unknown PC) within a map monitor/processing interval,
// that we would like to support.
bpf_map_def SEC("maps") pid_events = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(bool),
  .max_entries = 65536,
};

// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
bpf_map_def SEC("maps") pid_page_to_mapping_info = {
  .type        = BPF_MAP_TYPE_LPM_TRIE,
  .key_size    = sizeof(PIDPage),
  .value_size  = sizeof(PIDPageMappingInfo),
  .max_entries = 524288, // 2^19
  .map_flags   = BPF_F_NO_PREALLOC,
};

// inhibit_events map is used to inhibit sending events to user space.
//
// Only one event needs to be sent as it's a manual trigger to start processing
// traces / PIDs early. HA (Go) will reset this entry once it has reacted to the
// trigger, so next event is sent when needed.
// NOTE: Update .max_entries if additional event types are added. The value should
// equal the number of different event types using this mechanism.
bpf_map_def SEC("maps") inhibit_events = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(bool),
  .max_entries = 2,
};

// Perf event ring buffer for sending completed traces to user-mode.
//
// The map is periodically polled and read from in `tracer`.
bpf_map_def SEC("maps") trace_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(int),
  .value_size  = 0,
  .max_entries = 0,
};

// End shared maps

bpf_map_def SEC("maps") apm_int_procs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(pid_t),
  .value_size  = sizeof(ApmIntProcInfo),
  .max_entries = 128,
};

bpf_map_def SEC("maps") go_procs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(pid_t),
  .value_size  = sizeof(GoCustomLabelsOffsets),
  .max_entries = 128,
};

bpf_map_def SEC("maps") cl_procs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(pid_t),
  .value_size  = sizeof(NativeCustomLabelsProcInfo),
  .max_entries = 128,
};

static inline __attribute__((__always_inline__)) void *
get_m_ptr(struct GoCustomLabelsOffsets *offs, UnwindState *state)
{
  long res;

  size_t g_addr;
#if defined(__x86_64__)
  u64 g_addr_offset = 0xfffffffffffffff8;
  void *tls_base    = NULL;
  res               = tsd_get_base(&tls_base);
  if (res < 0) {
    DEBUG_PRINT("cl: failed to get tsd base; can't read m_ptr");
    return NULL;
  }

  res = bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((u64)tls_base + g_addr_offset));
  if (res < 0) {
    DEBUG_PRINT("cl: failed to read g_addr, tls_base(%lx)", (unsigned long)tls_base);
    return NULL;
  }
#elif defined(__aarch64__)
  g_addr = state->r28;
#endif

  DEBUG_PRINT("cl: reading m_ptr_addr at 0x%lx + 0x%x", g_addr, offs->m_offset);
  void *m_ptr_addr;
  res = bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m_offset));
  if (res < 0) {
    DEBUG_PRINT("cl: failed m_ptr_addr");
    return NULL;
  }

  return m_ptr_addr;
}

static inline __attribute__((__always_inline__)) void
maybe_add_go_custom_labels(struct pt_regs *ctx, PerCPURecord *record)
{
  u32 pid = record->trace.pid;
  // The Go label extraction code is too big to fit in this program, so we need to
  // tail call it, in order to keep the hashing and clearing code in this program it
  // will tail call back to us with this bool set.
  if (!record->state.processed_go_labels) {
    GoCustomLabelsOffsets *offsets = bpf_map_lookup_elem(&go_procs, &pid);
    if (!offsets) {
      DEBUG_PRINT("cl: no offsets, %d not recognized as a go binary", pid);
      return;
    }

    void *m_ptr_addr = get_m_ptr(offsets, &record->state);
    if (!m_ptr_addr) {
      return;
    }
    record->customLabelsState.go_m_ptr = m_ptr_addr;

    DEBUG_PRINT("cl: trace is within a process with Go custom labels enabled");
    increment_metric(metricID_UnwindGoCustomLabelsAttempts);
    record->state.processed_go_labels = true;
    tail_call(ctx, PROG_GO_LABELS);
  }
}

static inline __attribute__((__always_inline__)) bool
get_native_custom_labels(PerCPURecord *record, NativeCustomLabelsProcInfo *proc)
{
  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadTsdBase);
    DEBUG_PRINT("cl: failed to get TSD base for native custom labels");
    return false;
  }

  u64 offset = tsd_base + proc->tls_offset;
  DEBUG_PRINT("cl: native custom labels data at 0x%llx", offset);

  NativeCustomLabelsSet *p_current_set;
  int err;
  if ((err = bpf_probe_read_user(&p_current_set, sizeof(void *), (void *)(offset)))) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
    DEBUG_PRINT("Failed to read custom labels current set pointer: %d", err);
    return false;
  }

  if (!p_current_set) {
    DEBUG_PRINT("Null labelset");
    record->trace.custom_labels.len = 0;
    return true;
  }

  NativeCustomLabelsSet current_set;
  if ((err = bpf_probe_read_user(&current_set, sizeof(current_set), p_current_set))) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
    DEBUG_PRINT("cl: failed to read custom labels data: %d", err);
    return false;
  }

  DEBUG_PRINT("cl: native custom labels count: %lu", current_set.count);

  unsigned ct            = 0;
  CustomLabelsArray *out = &record->trace.custom_labels;

#pragma unroll
  for (int i = 0; i < MAX_CUSTOM_LABELS; i++) {
    if (i >= current_set.count)
      break;
    NativeCustomLabel *lbl_ptr = current_set.storage + i;
    if ((err = bpf_probe_read_user(
           &record->nativeCustomLabel, sizeof(NativeCustomLabel), (void *)(lbl_ptr)))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
      DEBUG_PRINT("cl: failed to read label storage struct: %d", err);
      return false;
    }
    NativeCustomLabel *lbl = &record->nativeCustomLabel;
    if (!lbl->key.buf)
      continue;
    CustomLabel *out_lbl = &out->labels[ct];
    unsigned klen        = MIN(lbl->key.len, CUSTOM_LABEL_MAX_KEY_LEN - 1);
    if ((err = bpf_probe_read_user(out_lbl->key, klen, (void *)lbl->key.buf))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadKey);
      DEBUG_PRINT("cl: failed to read label key: %d", err);
      goto exit;
    }
    unsigned vlen = MIN(lbl->value.len, CUSTOM_LABEL_MAX_VAL_LEN - 1);
    if ((err = bpf_probe_read_user(out_lbl->val, vlen, (void *)lbl->value.buf))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadValue);
      DEBUG_PRINT("cl: failed to read label value: %d", err);
      goto exit;
    }
    ++ct;
  }
exit:
  out->len = ct;
  increment_metric(metricID_UnwindNativeCustomLabelsReadSuccesses);
  return true;
}

static inline __attribute__((__always_inline__)) void
maybe_add_native_custom_labels(PerCPURecord *record)
{
  u32 pid                          = record->trace.pid;
  NativeCustomLabelsProcInfo *proc = bpf_map_lookup_elem(&cl_procs, &pid);
  if (!proc) {
    DEBUG_PRINT("cl: %d does not support native custom labels", pid);
    return;
  }
  DEBUG_PRINT("cl: trace is within a process with native custom labels enabled");
  bool success = get_native_custom_labels(record, proc);
  if (success)
    increment_metric(metricID_UnwindNativeCustomLabelsAddSuccesses);
  else
    increment_metric(metricID_UnwindNativeCustomLabelsAddErrors);
}

static inline __attribute__((__always_inline__)) void maybe_add_apm_info(Trace *trace)
{
  u32 pid              = trace->pid; // verifier needs this to be on stack on 4.15 kernel
  ApmIntProcInfo *proc = bpf_map_lookup_elem(&apm_int_procs, &pid);
  if (!proc) {
    return;
  }

  DEBUG_PRINT("Trace is within a process with APM integration enabled");

  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    increment_metric(metricID_UnwindApmIntErrReadTsdBase);
    DEBUG_PRINT("Failed to get TSD base for APM integration");
    return;
  }

  DEBUG_PRINT("APM corr ptr should be at 0x%llx", tsd_base + proc->tls_offset);

  void *apm_corr_buf_ptr;
  if (bpf_probe_read_user(
        &apm_corr_buf_ptr, sizeof(apm_corr_buf_ptr), (void *)(tsd_base + proc->tls_offset))) {
    increment_metric(metricID_UnwindApmIntErrReadCorrBufPtr);
    DEBUG_PRINT("Failed to read APM correlation buffer pointer");
    return;
  }

  ApmCorrelationBuf corr_buf;
  if (bpf_probe_read_user(&corr_buf, sizeof(corr_buf), apm_corr_buf_ptr)) {
    increment_metric(metricID_UnwindApmIntErrReadCorrBuf);
    DEBUG_PRINT("Failed to read APM correlation buffer");
    return;
  }

  if (corr_buf.trace_present && corr_buf.valid) {
    trace->apm_trace_id.as_int.hi    = corr_buf.trace_id.as_int.hi;
    trace->apm_trace_id.as_int.lo    = corr_buf.trace_id.as_int.lo;
    trace->apm_transaction_id.as_int = corr_buf.transaction_id.as_int;
  }

  increment_metric(metricID_UnwindApmIntReadSuccesses);

  // WARN: we print this as little endian
  DEBUG_PRINT(
    "APM transaction ID: %016llX, flags: 0x%02X",
    trace->apm_transaction_id.as_int,
    corr_buf.trace_flags);
}

// unwind_stop is the tail call destination for PROG_UNWIND_STOP.
static inline __attribute__((__always_inline__)) int unwind_stop(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;
  Trace *trace       = &record->trace;
  UnwindState *state = &record->state;

  // Do Go first since we might tail call out and back again.
  maybe_add_go_custom_labels(ctx, record);
  maybe_add_native_custom_labels(record);
  maybe_add_apm_info(trace);

  // If the stack is otherwise empty, push an error for that: we should
  // never encounter empty stacks for successful unwinding.
  if (trace->stack_len == 0 && trace->kernel_stack_id < 0) {
    DEBUG_PRINT("unwind_stop called but the stack is empty");
    increment_metric(metricID_ErrEmptyStack);
    if (!state->unwind_error) {
      state->unwind_error = ERR_EMPTY_STACK;
    }
  }

  // If unwinding was aborted due to a critical error, push an error frame.
  if (state->unwind_error) {
    DEBUG_PRINT("Aborting further unwinding due to error code %d", state->unwind_error);
    push_error(&record->trace, state->unwind_error);
  }

  switch (state->error_metric) {
  case -1:
    // No Error
    break;
  case metricID_UnwindNativeErrWrongTextSection:;
    if (report_pid(ctx, trace->pid, record->ratelimitAction)) {
      increment_metric(metricID_NumUnknownPC);
    }
    // Fallthrough to report the error
  default: increment_metric(state->error_metric);
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
  if (trace->stack_len == 1 && trace->kernel_stack_id < 0 && state->unwind_error) {
    u32 syscfg_key       = 0;
    SystemConfig *syscfg = bpf_map_lookup_elem(&system_config, &syscfg_key);
    if (!syscfg) {
      return -1; // unreachable
    }

    if (syscfg->drop_error_only_traces) {
      return 0;
    }
  }
  // TEMPORARY HACK END

  send_trace(ctx, trace);

  return 0;
}
MULTI_USE_FUNC(unwind_stop)

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version")    = 0xFFFFFFFE;
