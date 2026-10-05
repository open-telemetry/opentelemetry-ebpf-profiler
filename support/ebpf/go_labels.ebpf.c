// This file contains the code for extracting custom labels from Go runtime.

#include "bpfdefs.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// go_procs stores Go runtime-specific offsets per Go process.
struct go_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, GoRuntimeOffsets);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

static EBPF_INLINE bool golabel_push(Trace *trace, struct GoString *k, struct GoString *v)
{
  const u64 num_elems = sizeof(GolangLabel) / sizeof(trace->variable_data[0]);
  GolangLabel *l      = reserve_variable_data(trace, num_elems, 0);
  if (!l) {
    return false;
  }

  u64 klen = MIN(k->len, sizeof l->key - 1);
  if (bpf_probe_read_user(l->key, (u32)klen, k->str)) {
    DEBUG_PRINT("cl: failed to read label key (%lx)", (unsigned long)k->str);
    return false;
  }
  l->key[klen] = 0;

  u64 vlen = MIN(v->len, sizeof l->val - 1);
  if (bpf_probe_read_user(l->val, (u32)vlen, v->str)) {
    DEBUG_PRINT("cl: failed to read label value (%lx)", (unsigned long)v->str);
    return false;
  }
  l->val[vlen] = 0;
  commit_variable_data(trace, num_elems);

  return true;
}

static EBPF_INLINE bool
get_go_custom_labels_from_slice(PerCPURecord *record, void *labels_slice_ptr)
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
      goto done;
    if (!golabel_push(&record->trace, &record->goLabels[i], &record->goLabels[i + 1]))
      goto done;
  }
  ret = true;
done:
  return ret;
}

static EBPF_INLINE bool
get_go_custom_labels_from_map(PerCPURecord *record, void *labels_map_ptr_ptr)
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
  u16 max_end = record->trace.variable_data_end + sizeof(GolangLabel[MAX_GO_LABELS]) / 8;

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
      if (bucket->tophash[i] < minTopHash) {
        if (bucket->tophash[i] == emptyRest)
          break;
        continue;
      }
      if (record->trace.variable_data_end > max_end)
        goto done;
      if (!golabel_push(&record->trace, &bucket->keys[i], &bucket->values[i]))
        goto done;
    }
  }
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
static EBPF_INLINE bool get_go_custom_labels(PerCPURecord *record)
{
  GoRuntimeOffsets *offs = &record->goOffsets;
  size_t curg_ptr_addr;
  if (bpf_probe_read_user(
        &curg_ptr_addr,
        sizeof(void *),
        (void *)(record->golangLabelsState.go_m_ptr + offs->curg))) {
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
    return get_go_custom_labels_from_slice(record, labels_ptr);
  }
  // go 1.23- labels is a map
  return get_go_custom_labels_from_map(record, labels_ptr);
}

// go_labels is the entrypoint for extracting custom labels from Go runtime.
static EBPF_INLINE int go_labels(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  u32 pid = record->trace.pid;
  if (record->goOffsets.m_offset == 0) {
    DEBUG_PRINT("cl: no offsets, %d not recognized as a go binary", pid);
    return -1;
  }
  DEBUG_PRINT(
    "cl: go offsets found, %d recognized as a go binary: m_ptr: %lx",
    pid,
    (unsigned long)record->golangLabelsState.go_m_ptr);
  bool success = get_go_custom_labels(record);
  if (!success) {
    increment_metric(metricID_UnwindGoLabelsFailures);
  }
  record->trace.golang_label_end = record->trace.variable_data_end;

  send_trace(ctx, &record->trace);
  return 0;
}
MULTI_USE_FUNC(go_labels)
