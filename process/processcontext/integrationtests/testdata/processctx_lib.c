// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Shared library that defines a TLS variable. When loaded via dlopen(),
// this uses dynamic TLS (global-dynamic / TLS descriptor model), testing
// the dynamic TLS path in the threadcontext interpreter.

#include "processctx_lib.h"

#include "otel_process_ctx.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// The TLS variable that the threadcontext interpreter looks up.
// In a shared library, this will use the global-dynamic TLS model.
__thread otel_thread_ctx_v1_t *otel_thread_ctx_v1;

int init_process_context(void) {
  const char *attribute_key_map[] = {"http_route", "http_method", "user_id",
                                     NULL};
  const otel_thread_ctx_config_data thread_ctx_config = {
      .schema_version = "tlsdesc_v1_dev",
      .attribute_key_map = attribute_key_map,
  };
  const char *resource_attributes[] = {"resource.key1", "resource.value1",
                                       "resource.key2", "resource.value2",
                                       NULL};
  const char *extra_attributes[] = {"example_extra_attribute_foo",
                                    "example_extra_attribute_foo_value", NULL};

  otel_process_ctx_data data = {
      .deployment_environment_name = "prod",
      .service_instance_id = "123d8444-2c7e-46e3-89f6-6217880f7123",
      .service_name = "my-service",
      .service_version = "4.5.6",
      .telemetry_sdk_language = "c",
      .telemetry_sdk_version = "1.2.3",
      .telemetry_sdk_name = "example_ctx.c",
      .resource_attributes = resource_attributes,
      .extra_attributes = extra_attributes,
      .thread_ctx_config = &thread_ctx_config,
  };

  otel_process_ctx_result res = otel_process_ctx_publish(&data);
  if (!res.success) {
    fprintf(stderr, "Failed to publish: %s\n", res.error_message);
    return 1;
  }
  return 0;
}

void init_thread_context(size_t attrs_data_size) {
  otel_thread_ctx_v1 =
      malloc(sizeof(otel_thread_ctx_v1_t) + attrs_data_size);
  if (otel_thread_ctx_v1 == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
}

void update_thread_context(uint64_t span_id, uint64_t trace_id_lo,
                           uint64_t trace_id_hi, attribute_t *attrs,
                           size_t attrs_count) {
  otel_thread_ctx_v1->valid = 0;

  memcpy(otel_thread_ctx_v1->trace_id, &trace_id_lo,
         sizeof(trace_id_lo));
  memcpy(otel_thread_ctx_v1->trace_id + sizeof(trace_id_lo),
         &trace_id_hi, sizeof(trace_id_hi));
  memcpy(otel_thread_ctx_v1->span_id, &span_id, sizeof(span_id));

  size_t attr_pos = 0;
  for (size_t i = 0; i < attrs_count; ++i) {
    otel_thread_ctx_v1->attrs_data[attr_pos++] = attrs[i].key_index;
    size_t value_length = strlen(attrs[i].value);
    otel_thread_ctx_v1->attrs_data[attr_pos++] = value_length;
    memcpy(otel_thread_ctx_v1->attrs_data + attr_pos, attrs[i].value,
           value_length);
    attr_pos += value_length;
  }

  otel_thread_ctx_v1->attrs_data_size = attr_pos;
  otel_thread_ctx_v1->valid = 1;
}

void burn(int ms) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t start_time = ts.tv_sec * 1000000000 + ts.tv_nsec;
  while (1) {
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t current_time = ts.tv_sec * 1000000000 + ts.tv_nsec;
    if (current_time - start_time > ms * 1000000) {
      break;
    }
  }
}
