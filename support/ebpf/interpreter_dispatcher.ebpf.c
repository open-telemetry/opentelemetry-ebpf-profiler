// This file contains the code and map definitions that are shared between
// the tracers, as well as a dispatcher program that can be attached to a
// perf event and will call the appropriate tracer for a given process

#include "bpfdefs.h"
#include "hash.h"
#include "opaquify.h"
#include "kernel.h"
#include "types.h"
#include "tracemgmt.h"
#include "tsd.h"

// Begin shared maps

// Per-CPU record of the stack being built and meta-data on the building process
bpf_map_def SEC("maps") per_cpu_records = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(PerCPURecord),
  .max_entries = 1,
};

// metrics maps metric ID to a value
bpf_map_def SEC("maps") metrics = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = metricID_Max,
};

// progs maps from a program ID to an eBPF program
bpf_map_def SEC("maps") progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
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
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(u32),
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
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
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
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(bool),
  .max_entries = 65536,
};


// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
bpf_map_def SEC("maps") pid_page_to_mapping_info = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(PIDPage),
  .value_size = sizeof(PIDPageMappingInfo),
  .max_entries = 524288, // 2^19
  .map_flags = BPF_F_NO_PREALLOC,
};

// inhibit_events map is used to inhibit sending events to user space.
//
// Only one event needs to be sent as it's a manual trigger to start processing
// traces / PIDs early. HA (Go) will reset this entry once it has reacted to the
// trigger, so next event is sent when needed.
// NOTE: Update .max_entries if additional event types are added. The value should
// equal the number of different event types using this mechanism.
bpf_map_def SEC("maps") inhibit_events = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(bool),
  .max_entries = 2,
};

// Perf event ring buffer for sending completed traces to user-mode.
//
// The map is periodically polled and read from in `tracer`.
bpf_map_def SEC("maps") trace_events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = 0,
  .max_entries = 0,
};

// End shared maps

bpf_map_def SEC("maps") apm_int_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(ApmIntProcInfo),
  .max_entries = 128,
};

bpf_map_def SEC("maps") go_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(GoCustomLabelsOffsets),
  .max_entries = 128,
};

static inline __attribute__((__always_inline__))
void *get_m_ptr(struct GoCustomLabelsOffsets *offs, UnwindState *state) {
    long res;

    size_t g_addr;
#if defined(__x86_64__)
  u64 g_addr_offset = 0xfffffffffffffff8;
  void *tls_base = NULL;
  res = tsd_get_base(&tls_base);
  if (res < 0) {
    DEBUG_PRINT("Failed to get tsd base; can't read m_ptr");
    return NULL;
  }

  res = bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((u64)tls_base + g_addr_offset));
    if (res < 0) {
        DEBUG_PRINT("Failed to read g_addr");
        return NULL;
    }
#elif defined(__aarch64__)
    g_addr = state->r28;
#endif


    DEBUG_PRINT("reading m_ptr_addr at 0x%lx + 0x%x", g_addr, offs->m_offset);
    void *m_ptr_addr;
    res = bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m_offset));
    if (res < 0) {
        DEBUG_PRINT("Failed m_ptr_addr");
        return NULL;
    }

    return m_ptr_addr;
}

#define MAX_BUCKETS 8

// see https://gcc.gnu.org/onlinedocs/cpp/Stringizing.html#Stringizing
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

struct GoString {
    char *str;
    s64 len;
};

struct GoSlice {
    void *array;
    s64 len;
    s64 cap;
};

struct MapBucket {
    char tophash[8];
    struct GoString keys[8];
    struct GoString values[8];
    void *overflow;
};

bpf_map_def SEC("maps") golang_mapbucket_storage = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(struct MapBucket),
  .max_entries = 1,
};

bpf_map_def SEC("maps") custom_labels_storage = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(CustomLabelsArray),
  .max_entries = 1,
};

#define MAX_CUSTOM_LABELS_ENTRIES 1000

bpf_map_def SEC("maps") custom_labels = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(CustomLabelsArray),
  .max_entries = MAX_CUSTOM_LABELS_ENTRIES,
};


// Go processes store the current goroutine in thread local store. From there
// this reads the g (aka goroutine) struct, then the m (the actual operating
// system thread) of that goroutine, and finally curg (current goroutine). This
// chain is necessary because getg().m.curg points to the current user g
// assigned to the thread (curg == getg() when not on the system stack). curg
// may be nil if there is no user g, such as when running in the scheduler. If
// curg is nil, then g is either a system stack (called g0) or a signal handler
// g (gsignal). Neither one will ever have label.
static inline __attribute__((__always_inline__))
bool get_custom_labels(struct pt_regs *ctx, UnwindState *state, GoCustomLabelsOffsets *offs, CustomLabelsArray *out) {
    bpf_large_memzero((void *)out, sizeof(*out));
    long res;
    size_t m_ptr_addr = (size_t)get_m_ptr(offs, state);
    if (!m_ptr_addr) {
        return false;
    }

    size_t curg_ptr_addr;
    res = bpf_probe_read_user(&curg_ptr_addr, sizeof(void *), (void *)(m_ptr_addr + offs->curg));
    if (res < 0) {
        return false;
    }

    void *labels_map_ptr_ptr;
    res = bpf_probe_read_user(&labels_map_ptr_ptr, sizeof(void *), (void *)(curg_ptr_addr + offs->labels));
    if (res < 0) {
        return false;
    }

    void *labels_map_ptr;
    res = bpf_probe_read(&labels_map_ptr, sizeof(labels_map_ptr), labels_map_ptr_ptr);
    if (res < 0) {
        return false;
    }

    u64 labels_count = 0;
    res = bpf_probe_read(&labels_count, sizeof(labels_count), labels_map_ptr + offs->hmap_count);
    if (res < 0) {
        return false;
    }
    if (labels_count == 0) {
        return false;
    }

    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), labels_map_ptr + offs->hmap_log2_bucket_count);
    if (res < 0) {
        return false;
    }
    u64 bucket_count = 1 << log_2_bucket_count;
    void *label_buckets;
    res = bpf_probe_read(&label_buckets, sizeof(label_buckets), labels_map_ptr + offs->hmap_buckets);
    if (res < 0) {
        return false;
    }

    u32 map_id = 0;
    // This needs to be allocated in a per-cpu map, because it's too large and
    // can't be allocated on the stack (which is limited to 512 bytes in bpf).
    struct MapBucket *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage, &map_id);
    if (!map_value) {
        return false;
    }

    u64 len = 0;
    for (u64 j = 0; j < MAX_BUCKETS; j++) {
        if (j >= bucket_count) {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct MapBucket), label_buckets + (j * sizeof(struct MapBucket)));
        if (res < 0) {
            continue;
        }
        for (int i = 0; i < 8; ++i) {
            len = opaquify64(len, bucket_count);
            if (!(len < MAX_CUSTOM_LABELS))
                return true;
            if (map_value->tophash[i] == 0)
                continue;
            u64 key_len = map_value->keys[i].len;
            u64 val_len = map_value->values[i].len;
            CustomLabel *lbl = &out->labels[len];
            lbl->key_len = key_len;
            lbl->val_len = val_len;
            if (key_len > CUSTOM_LABEL_MAX_KEY_LEN) {
                DEBUG_PRINT("failed to read custom label: key too long");
                continue;
            }
            res = bpf_probe_read(lbl->key.key_bytes, key_len, map_value->keys[i].str);
            if (res) {
                DEBUG_PRINT("failed to read key for custom label: %ld", res);
                continue;
            }
            if (val_len > CUSTOM_LABEL_MAX_VAL_LEN) {
                DEBUG_PRINT("failed to read custom label: value too long");
                continue;
            }
            // The following assembly statement is equivalent to:
            // if (val_len > CUSTOM_LABEL_MAX_VAL_LEN)
            //     res = bpf_probe_read(lbl->val, val_len, map_value->values[i].str);
            // else
            //     res = -1;
            //
            // We need to write this in assembly because the verifier doesn't understand
            // that val_len has already been bounds-checked above, apparently
            // because clang has spilled it to the stack rather than
            // keeping it in a register.
          
            // clang-format off          
            asm volatile(
                // Note: this branch is never taken, but we
                // need it to appease the verifier.
                "if %2 > " STR(CUSTOM_LABEL_MAX_VAL_LEN) " goto 2f\n"
                "r1 = %1\n"
                "r2 = %2\n"
                "r3 = %3\n"
                "call 4\n"
                "%0 = r0\n"
                "goto 1f\n"
                "2: %0 = -1\n"
                "1:\n"
                : "=r"(res)
                : "r"(lbl->val.val_bytes), "r"(val_len), "r"(map_value->values[i].str)
                  // all r0-r5 are clobbered since we make a function call.
                : "r0", "r1", "r2", "r3", "r4", "r5", "memory"
            );
            // clang-format on
            if (res) {
                DEBUG_PRINT("failed to read value for custom label: %ld", res);
                continue;
            }
            ++len;
        }
    }

    out->len = len;
    return true;
}

static inline __attribute__((__always_inline__))
void maybe_add_go_custom_labels(struct pt_regs *ctx, Trace *trace, UnwindState *state) {
  u32 pid = trace->pid;
  GoCustomLabelsOffsets *offsets = bpf_map_lookup_elem(&go_procs, &pid);
  if (!offsets) {
    DEBUG_PRINT("no offsets, %d not recognized as a go binary", pid);
    return;
  }
  DEBUG_PRINT("Trace is within a process with Go custom labels enabled");
  increment_metric(metricID_UnwindGoCustomLabelsAttempts);
  u32 map_id = 0;
  CustomLabelsArray *lbls = bpf_map_lookup_elem(&custom_labels_storage, &map_id);
  bool success = false;
  if (lbls) {
    bool success = get_custom_labels(ctx, state, offsets, lbls);
    if (success) {
      DEBUG_PRINT("got %d custom labels", lbls->len);
      u64 hash;
      success = hash_custom_labels(lbls, 0, &hash);
      if (success) {
        int err = bpf_map_update_elem(&custom_labels, &hash, lbls, BPF_ANY);
        if (err) {
          DEBUG_PRINT("failed to update go custom labels with error %d\n", err);
        }
        else {
          trace->custom_labels_hash = hash;
          success = true;
          DEBUG_PRINT("successfully computed hash 0x%llx for Go custom labels", hash);
        }
      } else
        DEBUG_PRINT("failed to compute hash for go custom labels");
    } else
      DEBUG_PRINT("failed to get custom labels");
  } else
    DEBUG_PRINT("failed to get custom labels storage");
  if (!success)
    increment_metric(metricID_UnwindGoCustomLabelsFailures);
}

static inline __attribute__((__always_inline__))
void maybe_add_apm_info(Trace *trace) {
  u32 pid = trace->pid; // verifier needs this to be on stack on 4.15 kernel
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
  if (bpf_probe_read_user(&apm_corr_buf_ptr, sizeof(apm_corr_buf_ptr),
                          (void *)(tsd_base + proc->tls_offset))) {
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
    trace->apm_trace_id.as_int.hi = corr_buf.trace_id.as_int.hi;
    trace->apm_trace_id.as_int.lo = corr_buf.trace_id.as_int.lo;
    trace->apm_transaction_id.as_int = corr_buf.transaction_id.as_int;
  }

  increment_metric(metricID_UnwindApmIntReadSuccesses);

  // WARN: we print this as little endian
  DEBUG_PRINT("APM transaction ID: %016llX, flags: 0x%02X",
              trace->apm_transaction_id.as_int, corr_buf.trace_flags);
}

SEC("perf_event/unwind_stop")
int unwind_stop(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;
  Trace *trace = &record->trace;
  UnwindState *state = &record->state;

  maybe_add_apm_info(trace);
  maybe_add_go_custom_labels(ctx, trace, state);

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
  default:
    increment_metric(state->error_metric);
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
    u32 syscfg_key = 0;
    SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &syscfg_key);
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

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
