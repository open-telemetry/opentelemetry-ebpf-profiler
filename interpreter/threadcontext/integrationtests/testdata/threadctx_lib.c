// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Shared library that defines a TLS variable. When loaded via dlopen(),
// this uses dynamic TLS (global-dynamic / TLS descriptor model), testing
// the dynamic TLS path in the threadcontext interpreter.

#include "threadctx_lib.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// The TLS variable that the threadcontext interpreter looks up.
// In a shared library, this will use the global-dynamic TLS model.
__thread custom_labels_v2_tl_record_t *custom_labels_current_set_v2;

void init_thread_context(size_t attrs_data_size) {
    custom_labels_current_set_v2 = malloc(sizeof(custom_labels_v2_tl_record_t) + attrs_data_size);
    if (custom_labels_current_set_v2 == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
}

void update_thread_context(uint64_t span_id, uint64_t trace_id_lo, uint64_t trace_id_hi, attribute_t *attrs, size_t attrs_count) {
    custom_labels_current_set_v2->valid = 0;
    
    memcpy(custom_labels_current_set_v2->trace_id, &trace_id_lo, sizeof(trace_id_lo));
    memcpy(custom_labels_current_set_v2->trace_id + sizeof(trace_id_lo), &trace_id_hi, sizeof(trace_id_hi));
    memcpy(custom_labels_current_set_v2->span_id, &span_id, sizeof(span_id));

    size_t attr_pos = 0;
    for (size_t i = 0; i < attrs_count; ++i) {
        custom_labels_current_set_v2->attrs_data[attr_pos++] = attrs[i].key_index;
        custom_labels_current_set_v2->attrs_data[attr_pos++] = attrs[i].value_length;
        memcpy(custom_labels_current_set_v2->attrs_data + attr_pos, attrs[i].value, attrs[i].value_length);
        attr_pos += attrs[i].value_length;
    }

    custom_labels_current_set_v2->attrs_data_size = attr_pos;
    custom_labels_current_set_v2->valid = 1;
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
