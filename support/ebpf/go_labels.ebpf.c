// This file contains the code for extracting custom labels from Go runtime.

#include "bpfdefs.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"
#include "util.h"

static inline __attribute__((__always_inline__)) void
process_value(GoMapBucket *map_value, CustomLabelsArray *out, unsigned i)
{
  if (map_value->tophash[i] == 0)
    return;
  if (out->len >= MAX_CUSTOM_LABELS)
    return;
  CustomLabel *lbl = &out->labels[out->len];
  if (map_value->keys[i].str != NULL) {
    unsigned klen = MIN(map_value->keys[i].len, CUSTOM_LABEL_MAX_KEY_LEN - 1);
    long res      = bpf_probe_read_user(lbl->key, klen, map_value->keys[i].str);
    if (res) {
      DEBUG_PRINT(
        "cl: failed to read key for custom label (%lx): %ld",
        (unsigned long)map_value->keys[i].str,
        res);
      return;
    }
    unsigned vlen = MIN(map_value->values[i].len, CUSTOM_LABEL_MAX_VAL_LEN - 1);
    res           = bpf_probe_read_user(lbl->val, vlen, map_value->values[i].str);
    if (res) {
      DEBUG_PRINT("cl: failed to read value for custom label: %ld", res);
      return;
    }
  }
  out->len++;
}

static inline __attribute__((__always_inline__)) bool
process_bucket(PerCPURecord *record, void *label_buckets, int j)
{
  CustomLabelsArray *out = &record->trace.custom_labels;
  GoMapBucket *map_value = &record->goMapBucket;
  long res =
    bpf_probe_read_user(map_value, sizeof(GoMapBucket), label_buckets + (j * sizeof(GoMapBucket)));
  if (res < 0) {
    return false;
  }

  process_value(map_value, out, 0);
  process_value(map_value, out, 1);
  process_value(map_value, out, 2);
  process_value(map_value, out, 3);
  process_value(map_value, out, 4);
  process_value(map_value, out, 5);
  process_value(map_value, out, 6);
  process_value(map_value, out, 7);

  return false;
}

static inline __attribute__((__always_inline__)) void
process_slice_pair(PerCPURecord *record, struct GoSlice *labels_slice, int i)
{
  CustomLabelsArray *out = &record->trace.custom_labels;
  if (out->len >= MAX_CUSTOM_LABELS)
    return;

  CustomLabel *lbl = &out->labels[out->len];
  void *str_addr   = (char *)labels_slice->array + i * sizeof(struct GoString) * 2;
  long res         = bpf_probe_read_user(&record->labels, sizeof(struct GoString) * 2, str_addr);
  if (res < 0) {
    DEBUG_PRINT(
      "cl: failed to read strings from labels slice (%lx): %ld", (unsigned long)str_addr, res);
    return;
  }
  unsigned klen = MIN(record->labels[0].len, CUSTOM_LABEL_MAX_KEY_LEN - 1);
  res           = bpf_probe_read_user(lbl->key, klen, record->labels[0].str);
  if (res) {
    DEBUG_PRINT(
      "cl: failed to read key for custom label (%lx): %ld",
      (unsigned long)record->labels[0].str,
      res);
    return;
  }
  unsigned vlen = MIN(record->labels[1].len, CUSTOM_LABEL_MAX_VAL_LEN - 1);
  res           = bpf_probe_read_user(lbl->val, vlen, record->labels[1].str);
  if (res) {
    DEBUG_PRINT(
      "cl: failed to read key for custom label (%lx): %ld",
      (unsigned long)record->labels[1].str,
      res);
    return;
  }
  out->len++;
}

static inline __attribute__((__always_inline__)) bool
get_go_custom_labels_from_slice(struct pt_regs *ctx, PerCPURecord *record, void *labels_slice_ptr)
{
  // https://github.com/golang/go/blob/80e2e474/src/runtime/pprof/label.go#L20
  struct GoSlice labels_slice;
  long res = bpf_probe_read_user(&labels_slice, sizeof(struct GoSlice), labels_slice_ptr);
  if (res < 0) {
    DEBUG_PRINT(
      "cl: failed to read value for labels slice (%lx): %ld", (unsigned long)labels_slice_ptr, res);
    return false;
  }

  u64 label_count = MIN(MAX_CUSTOM_LABELS, labels_slice.len);
  switch (label_count) {
  case 10: process_slice_pair(record, &labels_slice, 9);
  case 9: process_slice_pair(record, &labels_slice, 8);
  case 8: process_slice_pair(record, &labels_slice, 7);
  case 7: process_slice_pair(record, &labels_slice, 6);
  case 6: process_slice_pair(record, &labels_slice, 5);
  case 5: process_slice_pair(record, &labels_slice, 4);
  case 4: process_slice_pair(record, &labels_slice, 3);
  case 3: process_slice_pair(record, &labels_slice, 2);
  case 2: process_slice_pair(record, &labels_slice, 1);
  case 1: process_slice_pair(record, &labels_slice, 0);
  }

  return true;
}

static inline __attribute__((__always_inline__)) bool get_go_custom_labels_from_map(
  struct pt_regs *ctx, PerCPURecord *record, void *labels_map_ptr_ptr, GoCustomLabelsOffsets *offs)
{
  void *labels_map_ptr;
  long res = bpf_probe_read_user(&labels_map_ptr, sizeof(labels_map_ptr), labels_map_ptr_ptr);
  if (res < 0) {
    DEBUG_PRINT(
      "cl: failed to read value for labels_map_ptr (%lx): %ld",
      (unsigned long)labels_map_ptr_ptr,
      res);
    return false;
  }

  u64 labels_count = 0;
  res = bpf_probe_read_user(&labels_count, sizeof(labels_count), labels_map_ptr + offs->hmap_count);
  if (res < 0) {
    DEBUG_PRINT("cl: failed to read value for labels_count: %ld", res);
    return false;
  }
  if (labels_count == 0) {
    DEBUG_PRINT("cl: no labels");
    return false;
  }

  unsigned char log_2_bucket_count;
  res = bpf_probe_read_user(
    &log_2_bucket_count, sizeof(log_2_bucket_count), labels_map_ptr + offs->hmap_log2_bucket_count);
  if (res < 0) {
    DEBUG_PRINT("cl: failed to read value for bucket_count: %ld", res);
    return false;
  }
  void *label_buckets;
  res =
    bpf_probe_read_user(&label_buckets, sizeof(label_buckets), labels_map_ptr + offs->hmap_buckets);
  if (res < 0) {
    DEBUG_PRINT("cl: failed to read value for label_buckets: %ld", res);
    return false;
  }

  // Manually unroll loop to support 4.19 kernel, auto unroll doesn't work as well
  // and we can't support as many buckets.
  u64 bucket_count = MIN(MAX_CUSTOM_LABELS, 1 << log_2_bucket_count);
  switch (bucket_count) {
  case 10:
    if (process_bucket(record, label_buckets, 9))
      return true;
  case 9:
    if (process_bucket(record, label_buckets, 8))
      return true;
  case 8:
    if (process_bucket(record, label_buckets, 7))
      return true;
  case 7:
    if (process_bucket(record, label_buckets, 6))
      return true;
  case 6:
    if (process_bucket(record, label_buckets, 5))
      return true;
  case 5:
    if (process_bucket(record, label_buckets, 4))
      return true;
  case 4:
    if (process_bucket(record, label_buckets, 3))
      return true;
  case 3:
    if (process_bucket(record, label_buckets, 2))
      return true;
  case 2:
    if (process_bucket(record, label_buckets, 1))
      return true;
  case 1:
    if (process_bucket(record, label_buckets, 0))
      return true;
  }

  return false;
}

// Go processes store the current goroutine in thread local store. From there
// this reads the g (aka goroutine) struct, then the m (the actual operating
// system thread) of that goroutine, and finally curg (current goroutine). This
// chain is necessary because getg().m.curg points to the current user g
// assigned to the thread (curg == getg() when not on the system stack). curg
// may be nil if there is no user g, such as when running in the scheduler. If
// curg is nil, then g is either a system stack (called g0) or a signal handler
// g (gsignal). Neither one will ever have label.
static inline __attribute__((__always_inline__)) bool
get_go_custom_labels(struct pt_regs *ctx, PerCPURecord *record, GoCustomLabelsOffsets *offs)
{
  long res;

  size_t curg_ptr_addr;
  res = bpf_probe_read_user(
    &curg_ptr_addr, sizeof(void *), (void *)(record->customLabelsState.go_m_ptr + offs->curg));
  if (res < 0) {
    DEBUG_PRINT("cl: failed to read value for m_ptr->curg: %ld", res);
    return false;
  }

  void *labels_ptr;
  res = bpf_probe_read_user(&labels_ptr, sizeof(void *), (void *)(curg_ptr_addr + offs->labels));
  if (res < 0) {
    DEBUG_PRINT(
      "cl: failed to read value for curg->labels (%lx->%lx): %ld",
      (unsigned long)curg_ptr_addr,
      (unsigned long)offs->labels,
      res);
    return false;
  }

  if (offs->hmap_buckets == 0) {
    // go 1.24+ labels is a slice
    return get_go_custom_labels_from_slice(ctx, record, labels_ptr);
  }

  // go 1.23- labels is a map
  return get_go_custom_labels_from_map(ctx, record, labels_ptr, offs);
}

SEC("perf_event/go_labels")
int perf_go_labels(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  u32 pid                        = record->trace.pid;
  GoCustomLabelsOffsets *offsets = bpf_map_lookup_elem(&go_procs, &pid);
  if (!offsets) {
    DEBUG_PRINT("cl: no offsets, %d not recognized as a go binary", pid);
    return -1;
  }
  DEBUG_PRINT(
    "cl: go offsets found, %d recognized as a go binary: m_ptr: %lx",
    pid,
    (unsigned long)record->customLabelsState.go_m_ptr);
  bool success = get_go_custom_labels(ctx, record, offsets);
  if (!success) {
    increment_metric(metricID_UnwindGoCustomLabelsFailures);
  }

  tail_call(ctx, PROG_UNWIND_STOP);
  return 0;
}
