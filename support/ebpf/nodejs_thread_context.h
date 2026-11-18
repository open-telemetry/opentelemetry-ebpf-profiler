// This file contains the walk from the otel_thread_ctx_nodejs_v1 discovery
// struct to the thread context record, per
// design-docs/01861-nodejs-thread-context.

#pragma once
#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "v8_tracer.h"

// The V8 layout is fixed by the nodejs_v1 schema, which admits only 64-bit
// builds without pointer compression and the V8 sandbox.

// NODE_TC_TAGGED_SIZE defines the width of a V8 tagged word.
#define NODE_TC_TAGGED_SIZE        8
// NODE_TC_JSMAP_TABLE_OFFSET defines the offset of the OrderedHashMap pointer
// within a JSMap.
#define NODE_TC_JSMAP_TABLE_OFFSET 24
// NODE_TC_FIXED_ARRAY_HEADER defines the FixedArray header size preceding the
// OrderedHashMap counts.
#define NODE_TC_FIXED_ARRAY_HEADER 16
// NODE_TC_HASH_COUNTS defines the number of count words ahead of the buckets.
#define NODE_TC_HASH_COUNTS        3
// NODE_TC_HASH_ENTRY_SIZE defines the words per entry: key, value and chain.
#define NODE_TC_HASH_ENTRY_SIZE    3
// NODE_TC_HASH_LOAD_FACTOR defines the entries per bucket V8 allocates.
#define NODE_TC_HASH_LOAD_FACTOR   2
// NODE_TC_MAX_CHAIN defines the bucket chain length walked before giving up.
#define NODE_TC_MAX_CHAIN          16

static EBPF_INLINE bool node_tc_is_smi(u64 word)
{
  return (word & V8_SmiTagMask) == V8_SmiTag;
}

static EBPF_INLINE s64 node_tc_smi(u64 word)
{
  return (s64)word >> V8_SmiValueShift;
}

static EBPF_INLINE bool node_tc_is_heap_object(u64 word)
{
  return (word & V8_HeapObjectTagMask) == V8_HeapObjectTag;
}

// node_tc_record walks from the discovery struct at tls_addr to the record the
// active async context frame holds for the published AsyncLocalStorage.
// Returns NULL when there is none, counting the failures among them.
static EBPF_INLINE void *node_tc_record(const void *tls_addr)
{
  NodeThreadCtx ctx;
  if (bpf_probe_read_user(&ctx, sizeof(ctx), tls_addr)) {
    increment_metric(metricID_UnwindThreadContextErrReadTlsPtr);
    return NULL;
  }

  // Zero until the SDK publishes on this thread, and again from teardown on.
  if (!ctx.cped_slot) {
    return NULL;
  }
  if (ctx.record_slot_offset % NODE_TC_TAGGED_SIZE) {
    goto invalid;
  }

  u64 frame;
  if (bpf_probe_read_user(&frame, sizeof(frame), (void *)ctx.cped_slot)) {
    goto read_err;
  }
  // The common case of a thread not serving a request.
  if (frame == ctx.undefined_addr) {
    return NULL;
  }
  if (!node_tc_is_heap_object(frame)) {
    goto invalid;
  }

  u64 key;
  if (bpf_probe_read_user(&key, sizeof(key), (void *)ctx.als_handle)) {
    goto read_err;
  }

  u64 table;
  if (bpf_probe_read_user(
        &table, sizeof(table), (void *)(frame - V8_HeapObjectTag + NODE_TC_JSMAP_TABLE_OFFSET))) {
    goto read_err;
  }
  if (!node_tc_is_heap_object(table)) {
    goto invalid;
  }
  const u64 data = table - V8_HeapObjectTag + NODE_TC_FIXED_ARRAY_HEADER;

  // FixedArray length, then the element, deleted and bucket counts.
  u64 hdr[4];
  if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)(data - NODE_TC_TAGGED_SIZE))) {
    goto read_err;
  }
  // A rehash leaves a pointer to the new table in the element count.
  if (
    !node_tc_is_smi(hdr[0]) || !node_tc_is_smi(hdr[1]) || !node_tc_is_smi(hdr[2]) ||
    !node_tc_is_smi(hdr[3])) {
    goto invalid;
  }
  s64 length   = node_tc_smi(hdr[0]);
  s64 elements = node_tc_smi(hdr[1]);
  s64 deleted  = node_tc_smi(hdr[2]);
  s64 buckets  = node_tc_smi(hdr[3]);
  if (buckets <= 0 || (buckets & (buckets - 1)) != 0 || elements < 0 || deleted < 0) {
    goto invalid;
  }
  s64 capacity = buckets * NODE_TC_HASH_LOAD_FACTOR;
  s64 used     = elements + deleted;
  if (
    used > capacity ||
    length < NODE_TC_HASH_COUNTS + buckets + NODE_TC_HASH_ENTRY_SIZE * capacity) {
    goto invalid;
  }

  u64 bucket = (u64)(u32)ctx.als_identity_hash & (u64)(buckets - 1);
  u64 head;
  if (bpf_probe_read_user(
        &head,
        sizeof(head),
        (void *)(data + (NODE_TC_HASH_COUNTS + bucket) * NODE_TC_TAGGED_SIZE))) {
    goto read_err;
  }

  // Entries fill in insertion order, so any index at or past used is a
  // terminator or garbage.
  s64 entry  = node_tc_is_smi(head) ? node_tc_smi(head) : -1;
  u64 value  = 0;
  bool found = false;
  for (u32 i = 0; i < NODE_TC_MAX_CHAIN; i++) {
    if (entry < 0 || entry >= used) {
      break;
    }
    u64 slot[NODE_TC_HASH_ENTRY_SIZE];
    u64 off = (u64)(NODE_TC_HASH_COUNTS + buckets + entry * NODE_TC_HASH_ENTRY_SIZE);
    if (bpf_probe_read_user(slot, sizeof(slot), (void *)(data + off * NODE_TC_TAGGED_SIZE))) {
      goto read_err;
    }
    if (slot[0] == key) {
      value = slot[1];
      found = true;
      break;
    }
    entry = node_tc_is_smi(slot[2]) ? node_tc_smi(slot[2]) : -1;
  }
  // Absent from this frame, or explicitly detached.
  if (!found || value == ctx.undefined_addr) {
    return NULL;
  }
  if (!node_tc_is_heap_object(value)) {
    goto invalid;
  }

  void *record;
  if (bpf_probe_read_user(
        &record, sizeof(record), (void *)(value - V8_HeapObjectTag + ctx.record_slot_offset))) {
    goto read_err;
  }
  return record;

read_err:
  increment_metric(metricID_UnwindThreadContextNodeErrRead);
  DEBUG_PRINT("Node.js thread context: failed to read the V8 heap");
  return NULL;

invalid:
  increment_metric(metricID_UnwindThreadContextNodeErrInvalid);
  DEBUG_PRINT("Node.js thread context: inconsistent V8 object");
  return NULL;
}
