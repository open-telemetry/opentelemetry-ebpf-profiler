// This file contains the code for extracting custom labels from Go runtime.

#include "bpfdefs.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// go_procs stores Go runtime-specific offsets per Go process.
struct go_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, GoRuntimeOffsets);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

static EBPF_INLINE int
get_go_custom_labels_from_slice(PerCPURecord *record, void *labels_slice_ptr)
{
  // https://github.com/golang/go/blob/80e2e474/src/runtime/pprof/label.go#L20
  struct GoSlice labels_slice;
  if (bpf_probe_read_user(&labels_slice, sizeof(struct GoSlice), labels_slice_ptr)) {
    DEBUG_PRINT("cl: failed to read value for labels slice (%lx)", (unsigned long)labels_slice_ptr);
    return -1;
  }

  // len is number of pairs, ie its a vector of key/val structs.
  u8 num_to_read = MIN(labels_slice.len, MAX_GO_LABELS);
  if (bpf_probe_read_user(
        &record->goLabels, sizeof(struct GoString) * 2 * num_to_read, labels_slice.array)) {
    DEBUG_PRINT(
      "cl: failed to read strings from labels slice (%lx)", (unsigned long)labels_slice.array);
    return -1;
  }
  return num_to_read;
}

static EBPF_INLINE int
get_go_custom_labels_from_map(PerCPURecord *record, void *labels_map_ptr_ptr)
{
  GoRuntimeOffsets *offs = &record->goOffsets;
  void *labels_map_ptr;
  if (bpf_probe_read_user(&labels_map_ptr, sizeof(labels_map_ptr), labels_map_ptr_ptr)) {
    DEBUG_PRINT(
      "cl: failed to read value for labels_map_ptr (%lx)", (unsigned long)labels_map_ptr_ptr);
    return -1;
  }

  u64 labels_count = 0;
  if (bpf_probe_read_user(&labels_count, sizeof(labels_count), labels_map_ptr + offs->hmap_count)) {
    DEBUG_PRINT("cl: failed to read value for labels_count");
    return -1;
  }
  if (labels_count == 0) {
    DEBUG_PRINT("cl: no labels");
    return 0;
  }

  unsigned char log_2_bucket_count;
  if (bpf_probe_read_user(
        &log_2_bucket_count,
        sizeof(log_2_bucket_count),
        labels_map_ptr + offs->hmap_log2_bucket_count)) {
    DEBUG_PRINT("cl: failed to read value for bucket_count");
    return -1;
  }
  void *label_buckets;
  if (bpf_probe_read_user(
        &label_buckets, sizeof(label_buckets), labels_map_ptr + offs->hmap_buckets)) {
    DEBUG_PRINT("cl: failed to read value for label_buckets");
    return -1;
  }

  // If the map has more than 16 buckets we just don't support it, pprof maps are typically
  // small and if its a problem upgrading to Go 1.24+ is a potential solution.
  u8 bucket_count = 1 << log_2_bucket_count;
  struct GoString *l = &record->goLabels[0];

  for (u8 b = 0; b < 16; b++) {
    if (b >= bucket_count)
      break;

    GoMapBucket *map_value = &record->goMapBucket;
    if (bpf_probe_read_user(map_value, sizeof(GoMapBucket), label_buckets)) {
      return -1;
    }
    label_buckets += sizeof(GoMapBucket);

    for (u8 i = 0; i < GO_MAP_BUCKET_SIZE; i++) {
      if (map_value->tophash[i] == 0)
        continue;
      if (map_value->keys[i].str == NULL)
        continue;

      *l++ = map_value->keys[i];
      *l++ = map_value->values[i];
      if (l >= &record->goLabels[2*MAX_GO_LABELS])
        break;
    }
  }
  return (unsigned int)(l - record->goLabels) >> 1;
}

// Pushes one Go label to the label data area.
static EBPF_INLINE u8 *
go_label_write(u8 *out, const u8 *end, const struct GoString *key, const struct GoString *val)
{
  u64 klen = MIN(key->len, 0xff);
  u64 vlen = MIN(val->len, 0xff);

  if (out + 2 + klen + vlen >= end) {
    return NULL;
  }
  *out++ = klen;
  *out++ = vlen;

  if (bpf_probe_read_user(out, klen, key->str)) {
    DEBUG_PRINT("cl: failed to read key for custom label (%lx)", (unsigned long)key->str);
    return NULL;
  }
  out += klen;

  if (bpf_probe_read_user(out, vlen, val->str)) {
    DEBUG_PRINT("cl: failed to read value for custom label (%lx)", (unsigned long)val->str);
    return NULL;
  }
  out += vlen;
  return out;
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
        (void *)(record->customLabelsState.go_m_ptr + offs->curg))) {
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

  int num_labels;
  if (offs->hmap_buckets == 0) {
    // go 1.24+ labels is a slice
    num_labels = get_go_custom_labels_from_slice(record, labels_ptr);
      return false;
  } else {
    // go 1.23- labels is a map
    num_labels = get_go_custom_labels_from_map(record, labels_ptr);
  }
  if (num_labels < 0)
    return false;

  // Convert the data from the scratch array to event label data payload
  const int elems = sizeof(record->trace.variable_data) / sizeof(record->trace.variable_data[0]);
  u8 *start = (u8*) &record->trace.variable_data[record->trace.frame_data_len];
  u8 *end = (u8*) &record->trace.variable_data[elems];
  u8 *out = start;

  const struct GoString *label = &record->goLabels[0];
  bool ret = false;
  for (u8 i = 0; i < MAX_GO_LABELS; i++, label += 2) {
    if (i >= num_labels)
      break;
    out = go_label_write(out, end, &label[0], &label[1]);
    if (out == NULL)
      goto done;
  }
  ret = true;
done:
  record->trace.label_data_bytes = out - start;
  return ret;
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
    (unsigned long)record->customLabelsState.go_m_ptr);
  bool success = get_go_custom_labels(record);
  if (!success) {
    increment_metric(metricID_UnwindGoLabelsFailures);
  }

  send_trace(ctx, &record->trace);
  return 0;
}
MULTI_USE_FUNC(go_labels)
