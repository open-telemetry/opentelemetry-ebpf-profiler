// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct __attribute__((packed)) {
  // W3C trace context fields
  uint8_t trace_id[16];
  uint8_t span_id[8];

  // Readers should ignore this record if valid is 0
  uint8_t valid;

  // Explicit padding for alignment of attrs_data_size
  uint8_t _padding;

  // Size of attrs_data in bytes (lets reader know when to stop parsing)
  uint16_t attrs_data_size;

  // Attribute data; each attr is [key_index:1][length:1][value:length]
  // This is stored without padding to a constant length (like the key table)
  // so that we squeeze as much data as we can into each context update.
  uint8_t attrs_data[];
} otel_thread_ctx_v1_t;

typedef struct {
  uint8_t key_index;
  const char *value;
} attribute_t;

#ifndef USE_DLOPEN
int init_process_context(void);
void init_thread_context(size_t attrs_data_size);
void update_thread_context(uint64_t span_id, uint64_t trace_id_lo,
                           uint64_t trace_id_hi, attribute_t *attrs,
                           size_t attrs_count);
void burn(int ms);
#endif
