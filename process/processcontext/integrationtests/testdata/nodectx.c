// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Publishes a thread context record the way a Node.js SDK does, per
// design-docs/01861-nodejs-thread-context. The V8 objects on the walk are laid
// out by hand in the default 64-bit build layout, so no Node.js is needed.

#include "nodectx.h"

#include <stdint.h>

typedef struct {
  uint64_t cped_slot;
  uint64_t als_handle;
  int32_t als_identity_hash;
  uint8_t record_slot_offset;
  uint8_t reserved[3];
  uint64_t undefined_addr;
} otel_thread_ctx_nodejs_v1_t;

__thread otel_thread_ctx_nodejs_v1_t otel_thread_ctx_nodejs_v1;

#define TAGGED(p) ((uint64_t)(uintptr_t)(p) | 1)
#define SMI(v) ((uint64_t)(int64_t)(v) << 32)

#define ALS_HASH 0x2a
#define BUCKETS 2
#define CAPACITY (BUCKETS * 2)
// Record slot offset of Node.js 23 and later.
#define RECORD_SLOT_OFFSET 32

typedef uint64_t heap_object[8] __attribute__((aligned(8)));

static heap_object undefined_obj, als_obj, decoy_obj, frame_obj, wrapper_obj;
// The v8::Global of the AsyncLocalStorage.
static uint64_t als_global;
static uint64_t cped;
// FixedArray header, the three counts, bucket heads, then the entries.
static uint64_t table[2 + 3 + BUCKETS + 3 * CAPACITY];

void nodectx_publish(void *record) {
  uint64_t *words = table + 2;
  table[1] = SMI(3 + BUCKETS + 3 * CAPACITY);
  words[0] = SMI(2); // elements
  words[1] = SMI(0); // deleted
  words[2] = SMI(BUCKETS);

  // Both entries share the AsyncLocalStorage's bucket, the decoy at the chain
  // head, so the walk has to follow the chain.
  uint64_t *heads = words + 3;
  uint64_t *entries = heads + BUCKETS;
  for (int i = 0; i < BUCKETS; i++) {
    heads[i] = SMI(-1);
  }
  heads[ALS_HASH & (BUCKETS - 1)] = SMI(1);
  entries[0] = TAGGED(als_obj);
  entries[1] = TAGGED(wrapper_obj);
  entries[2] = SMI(-1);
  entries[3] = TAGGED(decoy_obj);
  entries[4] = TAGGED(undefined_obj);
  entries[5] = SMI(0);

  frame_obj[3] = TAGGED(table);
  wrapper_obj[RECORD_SLOT_OFFSET / 8] = (uint64_t)(uintptr_t)record;
  als_global = TAGGED(als_obj);
  cped = TAGGED(frame_obj);

  volatile otel_thread_ctx_nodejs_v1_t *ctx = &otel_thread_ctx_nodejs_v1;
  ctx->als_handle = (uint64_t)(uintptr_t)&als_global;
  ctx->als_identity_hash = ALS_HASH;
  ctx->record_slot_offset = RECORD_SLOT_OFFSET;
  ctx->undefined_addr = TAGGED(undefined_obj);
  // The gate goes last.
  __atomic_signal_fence(__ATOMIC_SEQ_CST);
  ctx->cped_slot = (uint64_t)(uintptr_t)&cped;
}
