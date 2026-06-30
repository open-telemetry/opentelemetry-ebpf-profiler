// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License (Version 2.0). This product includes software
// developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog,
// Inc.

#include "otel_process_ctx.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef __cplusplus
#include <atomic>
using std::atomic_thread_fence;
using std::memory_order_seq_cst;
#else
#include <stdatomic.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#define ADD_QUOTES_HELPER(x) #x
#define ADD_QUOTES(x) ADD_QUOTES_HELPER(x)
#define KEY_VALUE_LIMIT 4096
#define UINT14_MAX 16383
#define OTEL_CTX_SIGNATURE "OTEL_CTX"

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 8U
#endif

static const otel_process_ctx_data empty_data = {.deployment_environment_name =
                                                     NULL,
                                                 .service_instance_id = NULL,
                                                 .service_name = NULL,
                                                 .service_version = NULL,
                                                 .telemetry_sdk_language = NULL,
                                                 .telemetry_sdk_version = NULL,
                                                 .telemetry_sdk_name = NULL,
                                                 .resource_attributes = NULL,
                                                 .extra_attributes = NULL,
                                                 .thread_ctx_config = NULL};

#if (defined(OTEL_PROCESS_CTX_NOOP) && OTEL_PROCESS_CTX_NOOP) ||               \
    !defined(__linux__)
// NOOP implementations when OTEL_PROCESS_CTX_NOOP is defined or not on Linux

otel_process_ctx_result
otel_process_ctx_publish(const otel_process_ctx_data *data) {
  (void)data; // Suppress unused parameter warning
  return (otel_process_ctx_result){.success = false,
                                   .error_message =
                                       "OTEL_PROCESS_CTX_NOOP mode is enabled "
                                       "- no-op implementation (" __FILE__
                                       ":" ADD_QUOTES(__LINE__) ")"};
}

bool otel_process_ctx_drop_current(void) {
  return true; // Nothing to do, this always succeeds
}

#ifndef OTEL_PROCESS_CTX_NO_READ
otel_process_ctx_read_result otel_process_ctx_read(void) {
  return (otel_process_ctx_read_result){
      .success = false,
      .error_message = "OTEL_PROCESS_CTX_NOOP mode is enabled - no-op "
                       "implementation (" __FILE__ ":" ADD_QUOTES(__LINE__) ")",
      .data = empty_data};
}

bool otel_process_ctx_read_drop(otel_process_ctx_read_result *result) {
  (void)result; // Suppress unused parameter warning
  return false;
}
#endif // OTEL_PROCESS_CTX_NO_READ
#else  // OTEL_PROCESS_CTX_NOOP

/**
 * The process context data that's written into the published anonymous mapping.
 *
 * An outside-of-process reader will read this struct + otel_process_payload to
 * get the data.
 */
typedef struct __attribute__((packed, aligned(8))) {
  char otel_process_ctx_signature[8]; // Always "OTEL_CTX"
  uint32_t otel_process_ctx_version;  // Always > 0, incremented when the data
                                      // structure changes, currently v2
  uint32_t otel_process_payload_size; // Always > 0, size of storage
  uint64_t
      otel_process_monotonic_published_at_ns; // Timestamp from when the context
                                              // was published in nanoseconds
                                              // from CLOCK_BOOTTIME. 0 during
                                              // updates.
  char *otel_process_payload; // Always non-null, points to the storage for the
                              // data; expected to be a protobuf map of string
                              // key/value pairs, null-terminated
} otel_process_ctx_mapping;

/**
 * The full state of a published process context.
 *
 * It is used to store the all data for the process context and that needs to be
 * kept around while the context is published.
 */
typedef struct {
  // The pid of the process that published the context.
  pid_t publisher_pid;
  // The actual mapping of the process context. Note that because we
  // `madvise(..., MADV_DONTFORK)` this mapping is not propagated to child
  // processes and thus `mapping` is only valid on the process that published
  // the context.
  otel_process_ctx_mapping *mapping;
  // The process context payload.
  char *payload;
} otel_process_ctx_state;

/**
 * Only one context is active, so we keep its state as a global.
 */
static otel_process_ctx_state published_state;

static otel_process_ctx_result
otel_process_ctx_update(uint64_t monotonic_published_at_ns,
                        const otel_process_ctx_data *data);
static otel_process_ctx_result
otel_process_ctx_encode_protobuf_payload(char **out, uint32_t *out_size,
                                         otel_process_ctx_data data);

static uint64_t monotonic_time_now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_BOOTTIME, &ts) == -1)
    return 0;
  return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static bool ctx_is_published(otel_process_ctx_state state) {
  return state.mapping != NULL && state.mapping != MAP_FAILED &&
         getpid() == state.publisher_pid;
}

// The process context is designed to be read by an outside-of-process reader.
// Thus, for concurrency purposes the steps on this method are ordered in a way
// to avoid races, or if not possible to avoid, to allow the reader to detect if
// there was a race.
otel_process_ctx_result
otel_process_ctx_publish(const otel_process_ctx_data *data) {
  if (!data)
    return (otel_process_ctx_result){
        .success = false,
        .error_message = "otel_process_ctx_data is NULL (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")"};

  uint64_t monotonic_published_at_ns = monotonic_time_now_ns();
  if (monotonic_published_at_ns == 0) {
    return (otel_process_ctx_result){.success = false,
                                     .error_message =
                                         "Failed to get current time (" __FILE__
                                         ":" ADD_QUOTES(__LINE__) ")"};
  }

  // Step: If the context has been published by this process, update it in place
  if (ctx_is_published(published_state))
    return otel_process_ctx_update(monotonic_published_at_ns, data);

  // Step: Drop any previous context state if it exists
  // No state should be around anywhere after this step.
  if (!otel_process_ctx_drop_current()) {
    return (otel_process_ctx_result){
        .success = false,
        .error_message = "Failed to drop previous context (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")"};
  }

  // Step: Prepare the payload to be published
  // The payload SHOULD be ready and valid before trying to actually create the
  // mapping.
  uint32_t payload_size = 0;
  otel_process_ctx_result result = otel_process_ctx_encode_protobuf_payload(
      &published_state.payload, &payload_size, *data);
  if (!result.success)
    return result;

  // Step: Create the mapping
  const ssize_t mapping_size = sizeof(otel_process_ctx_mapping);
  published_state.publisher_pid =
      getpid(); // This allows us to detect in forks that we shouldn't touch the
                // mapping
  int fd = memfd_create("OTEL_CTX",
                        MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL);
  if (fd < 0) {
    // MFD_NOEXEC_SEAL is a newer flag; older kernels reject unknown flags, so
    // let's retry without it
    fd = memfd_create("OTEL_CTX", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  }
  bool failed_to_close_fd = false;
  if (fd >= 0) {
    // Try to create mapping from memfd
    if (ftruncate(fd, mapping_size) == -1) {
      otel_process_ctx_drop_current();
      return (otel_process_ctx_result){.success = false,
                                       .error_message =
                                           "Failed to truncate memfd (" __FILE__
                                           ":" ADD_QUOTES(__LINE__) ")"};
    }
    published_state.mapping = (otel_process_ctx_mapping *)mmap(
        NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    failed_to_close_fd = (close(fd) == -1);
  } else {
    // Fallback: Use an anonymous mapping instead
    published_state.mapping = (otel_process_ctx_mapping *)mmap(
        NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);
  }
  if (published_state.mapping == MAP_FAILED || failed_to_close_fd) {
    otel_process_ctx_drop_current();

    if (failed_to_close_fd) {
      return (otel_process_ctx_result){.success = false,
                                       .error_message =
                                           "Failed to close memfd (" __FILE__
                                           ":" ADD_QUOTES(__LINE__) ")"};
    } else {
      return (otel_process_ctx_result){
          .success = false,
          .error_message = "Failed to allocate mapping (" __FILE__
                           ":" ADD_QUOTES(__LINE__) ")"};
    }
  }

  // Step: Setup MADV_DONTFORK
  // This ensures that the mapping is not propagated to child processes (they
  // should call update/publish again).
  if (madvise(published_state.mapping, mapping_size, MADV_DONTFORK) == -1) {
    if (otel_process_ctx_drop_current()) {
      return (otel_process_ctx_result){
          .success = false,
          .error_message = "Failed to setup MADV_DONTFORK (" __FILE__
                           ":" ADD_QUOTES(__LINE__) ")"};
    } else {
      return (otel_process_ctx_result){.success = false,
                                       .error_message =
                                           "Failed to drop context (" __FILE__
                                           ":" ADD_QUOTES(__LINE__) ")"};
    }
  }

  // Step: Populate the mapping
  // The payload and any extra fields must come first and not be reordered with
  // the monotonic_published_at_ns by the compiler.
  *published_state.mapping = (otel_process_ctx_mapping){
      .otel_process_ctx_signature = {'O', 'T', 'E', 'L', '_', 'C', 'T', 'X'},
      .otel_process_ctx_version = 2,
      .otel_process_payload_size = payload_size,
      .otel_process_monotonic_published_at_ns =
          0, // Set in "Step: Populate the monotonic_published_at_ns into the
             // mapping" below
      .otel_process_payload = published_state.payload};

  // Step: Synchronization - Mapping has been filled and is missing
  // monotonic_published_at_ns Make sure the initialization of the mapping +
  // payload above does not get reordered with setting the
  // monotonic_published_at_ns below. Setting the monotonic_published_at_ns is
  // what tells an outside reader that the context is fully published.
  atomic_thread_fence(memory_order_seq_cst);

  // Step: Populate the monotonic_published_at_ns into the mapping
  // The monotonic_published_at_ns must come last and not be reordered with the
  // fields above by the compiler. After this step, external readers can read
  // the monotonic_published_at_ns and know that the payload is ready to be
  // read.
  published_state.mapping->otel_process_monotonic_published_at_ns =
      monotonic_published_at_ns;

  // Step: Attempt to name the mapping so outside readers can:
  // * Find it by name
  // * Hook on prctl to detect when new mappings are published
  if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, published_state.mapping,
            mapping_size, OTEL_CTX_SIGNATURE) == -1) {
    // Naming an anonymous mapping is an optional Linux 5.17+ feature
    // (`CONFIG_ANON_VMA_NAME`). Many distros, such as Ubuntu and Arch enable
    // it. On earlier kernel versions or kernels without the feature, this call
    // can fail.
    //
    // It's OK for this to fail because (per-usecase):
    // 1. "Find it by name" => As a fallback, it's possible to scan the mappings
    // and for the memfd name.
    // 2. "Hook on prctl" => When hooking on prctl via eBPF it's still possible
    // to see this call, even when it's not supported/enabled.
    //    This works even on older kernels! For this reason we unconditionally
    //    make this call even on older kernels -- to still allow detection via
    //    hooking onto prctl.
  }

  // All done!

  return (otel_process_ctx_result){.success = true, .error_message = NULL};
}

bool otel_process_ctx_drop_current(void) {
  otel_process_ctx_state state = published_state;

  // Zero out the state and make sure no operations below are reordered with
  // zeroing
  published_state = (otel_process_ctx_state){
      .publisher_pid = 0, .mapping = NULL, .payload = NULL};
  atomic_thread_fence(memory_order_seq_cst);

  bool success = true;

  // The mapping only exists if it was created by the current process; if it was
  // inherited by a fork it doesn't exist anymore (due to the MADV_DONTFORK) and
  // we don't need to do anything to it.
  if (ctx_is_published(state)) {
    success = munmap(state.mapping, sizeof(otel_process_ctx_mapping)) == 0;
  }

  // The payload may have been inherited from a parent. This is a regular malloc
  // so we need to free it so we don't leak.
  free(state.payload);

  return success;
}

static otel_process_ctx_result
otel_process_ctx_update(uint64_t monotonic_published_at_ns,
                        const otel_process_ctx_data *data) {
  if (data == NULL || !ctx_is_published(published_state)) {
    return (otel_process_ctx_result){
        .success = false,
        .error_message =
            "Unexpected: otel_process_ctx_data is NULL or context is not "
            "published (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  if (monotonic_published_at_ns ==
      published_state.mapping->otel_process_monotonic_published_at_ns) {
    // Advance published_at_ns to allow readers to detect the update
    monotonic_published_at_ns++;
  }

  // Step: Prepare the new payload to be published
  // The payload SHOULD be ready and valid before trying to actually update the
  // mapping.
  uint32_t payload_size = 0;
  char *payload;
  otel_process_ctx_result result =
      otel_process_ctx_encode_protobuf_payload(&payload, &payload_size, *data);
  if (!result.success)
    return result;

  // Step: Zero out monotonic_published_at_ns in the mapping
  // This enables readers to detect that an update is in-progress
  published_state.mapping->otel_process_monotonic_published_at_ns = 0;

  // Step: Synchronization - Make sure readers observe the zeroing above before
  // anything else below
  atomic_thread_fence(memory_order_seq_cst);

  // Step: Install updated data
  published_state.mapping->otel_process_payload_size = payload_size;
  published_state.mapping->otel_process_payload = payload;

  // Step: Synchronization - Make sure readers observe the updated data before
  // anything else below
  atomic_thread_fence(memory_order_seq_cst);

  // Step: Install new monotonic_published_at_ns
  // The update is now complete -- readers that observe the new timestamp will
  // observe the updated payload
  published_state.mapping->otel_process_monotonic_published_at_ns =
      monotonic_published_at_ns;

  // Step: Attempt to name the mapping so outside readers can detect the update
  if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, published_state.mapping,
            sizeof(otel_process_ctx_mapping), OTEL_CTX_SIGNATURE) == -1) {
    // It's OK for this to fail -- see otel_process_ctx_publish for why
  }

  // Step: Update bookkeeping
  free(published_state.payload); // This was still pointing to the old payload
  published_state.payload = payload;

  // All done!

  return (otel_process_ctx_result){.success = true, .error_message = NULL};
}

// The caller is responsible for enforcing that value fits within UINT14_MAX
static size_t protobuf_varint_size(uint16_t value) {
  return value >= 128 ? 2 : 1;
}

// Field tag for record + varint len + data
static size_t protobuf_record_size(size_t len) {
  return 1 + protobuf_varint_size(len) + len;
}

static size_t protobuf_string_size(const char *str) {
  return protobuf_record_size(strlen(str));
}

static size_t protobuf_otel_keyvalue_string_size(const char *key,
                                                 const char *value) {
  size_t key_field_size = protobuf_string_size(key); // String
  size_t value_field_size = protobuf_record_size(protobuf_string_size(
      value)); // Nested AnyValue message with a string inside
  return key_field_size +
         value_field_size; // Does not include the keyvalue record tag + size,
                           // only its payload
}

static size_t protobuf_otel_array_value_content_size(const char **strings) {
  size_t total = 0;
  for (size_t i = 0; strings[i] != NULL; i++) {
    total += protobuf_record_size(protobuf_string_size(
        strings[i])); // ArrayValue.values[i]: AnyValue{string_value}
  }
  return total;
}

// As a simplification, we enforce that keys and values are <= 4096
// (KEY_VALUE_LIMIT) so that their size + extra bytes always fits within
// UINT14_MAX
static otel_process_ctx_result
validate_and_calculate_protobuf_payload_size(size_t *out_pairs_size,
                                             const char **pairs) {
  size_t num_entries = 0;
  for (size_t i = 0; pairs[i] != NULL; i++)
    num_entries++;
  if (num_entries % 2 != 0) {
    return (otel_process_ctx_result){
        .success = false,
        .error_message = "Value in otel_process_ctx_data is NULL (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")"};
  }

  *out_pairs_size = 0;
  for (size_t i = 0; pairs[i * 2] != NULL; i++) {
    const char *key = pairs[i * 2];
    const char *value = pairs[i * 2 + 1];

    if (strlen(key) > KEY_VALUE_LIMIT) {
      return (otel_process_ctx_result){
          .success = false,
          .error_message =
              "Length of key in otel_process_ctx_data exceeds 4096 limit "
              "(" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }
    if (strlen(value) > KEY_VALUE_LIMIT) {
      return (otel_process_ctx_result){
          .success = false,
          .error_message =
              "Length of value in otel_process_ctx_data exceeds 4096 limit "
              "(" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }

    *out_pairs_size += protobuf_record_size(
        protobuf_otel_keyvalue_string_size(key, value)); // KeyValue message
  }
  return (otel_process_ctx_result){.success = true, .error_message = NULL};
}

/**
 * Writes a protobuf varint encoding for the given value.
 * As a simplification, only supports values that fit in 1 or 2 bytes (0-16383
 * UINT14_MAX).
 */
static void write_protobuf_varint(char **ptr, uint16_t value) {
  if (protobuf_varint_size(value) == 1) {
    *(*ptr)++ = (char)value;
  } else {
    // Two bytes: first byte has MSB set, second byte has value
    *(*ptr)++ = (char)((value & 0x7F) | 0x80); // Low 7 bits + continuation bit
    *(*ptr)++ = (char)(value >> 7);            // High 7 bits
  }
}

static void write_protobuf_string(char **ptr, const char *str) {
  size_t len = strlen(str);
  write_protobuf_varint(ptr, len);
  memcpy(*ptr, str, len);
  *ptr += len;
}

static void write_protobuf_tag(char **ptr, uint8_t field_number) {
  *(*ptr)++ = (char)((field_number << 3) | 2); // Field type is always 2 (LEN)
}

static void write_attribute(char **ptr, uint8_t field_number, const char *key,
                            const char *value) {
  write_protobuf_tag(ptr, field_number);
  write_protobuf_varint(ptr, protobuf_otel_keyvalue_string_size(key, value));

  // KeyValue
  write_protobuf_tag(ptr, 1); // KeyValue.key (field 1)
  write_protobuf_string(ptr, key);
  write_protobuf_tag(ptr, 2); // KeyValue.value (field 2)
  write_protobuf_varint(ptr, protobuf_string_size(value));

  // AnyValue
  write_protobuf_tag(ptr, 1); // AnyValue.string_value (field 1)
  write_protobuf_string(ptr, value);
}

static void write_array_attribute(char **ptr, uint8_t field_number,
                                  const char *key, const char **strings) {
  size_t array_value_content_size =
      protobuf_otel_array_value_content_size(strings);
  size_t any_value_content_size =
      protobuf_record_size(array_value_content_size);
  size_t kv_content_size =
      protobuf_string_size(key) + protobuf_record_size(any_value_content_size);

  write_protobuf_tag(ptr, field_number);
  write_protobuf_varint(ptr, kv_content_size);

  write_protobuf_tag(ptr, 1); // KeyValue.key (field 1)
  write_protobuf_string(ptr, key);

  write_protobuf_tag(ptr, 2); // KeyValue.value (field 2) = AnyValue message
  write_protobuf_varint(ptr, any_value_content_size);

  write_protobuf_tag(ptr,
                     5); // AnyValue.array_value (field 5) = ArrayValue message
  write_protobuf_varint(ptr, array_value_content_size);

  for (size_t i = 0; strings[i] != NULL;
       i++) { // ArrayValue.values (field 1) - repeated AnyValue entries
    write_protobuf_tag(ptr, 1); // ArrayValue.values[i]
    write_protobuf_varint(
        ptr, protobuf_string_size(strings[i])); // Inner AnyValue size
    write_protobuf_tag(ptr, 1); // AnyValue.string_value (field 1)
    write_protobuf_string(ptr, strings[i]);
  }
}

// Encode the payload as protobuf bytes.
//
// This method implements an extremely compact but limited protobuf encoder for
// the ProcessContext message. It encodes all fields as Resource attributes
// (KeyValue pairs). For extra compact code, it fixes strings at up to 4096
// bytes.
static otel_process_ctx_result
otel_process_ctx_encode_protobuf_payload(char **out, uint32_t *out_size,
                                         otel_process_ctx_data data) {
  const char *pairs[] = {"deployment.environment.name",
                         data.deployment_environment_name,
                         "service.instance.id",
                         data.service_instance_id,
                         "service.name",
                         data.service_name,
                         "service.version",
                         data.service_version,
                         "telemetry.sdk.language",
                         data.telemetry_sdk_language,
                         "telemetry.sdk.version",
                         data.telemetry_sdk_version,
                         "telemetry.sdk.name",
                         data.telemetry_sdk_name,
                         NULL};

  size_t pairs_size = 0;
  otel_process_ctx_result validation_result =
      validate_and_calculate_protobuf_payload_size(&pairs_size,
                                                   (const char **)pairs);
  if (!validation_result.success)
    return validation_result;

  size_t resource_attributes_pairs_size = 0;
  if (data.resource_attributes != NULL) {
    validation_result = validate_and_calculate_protobuf_payload_size(
        &resource_attributes_pairs_size, data.resource_attributes);
    if (!validation_result.success)
      return validation_result;
  }

  size_t extra_attributes_pairs_size = 0;
  if (data.extra_attributes != NULL) {
    validation_result = validate_and_calculate_protobuf_payload_size(
        &extra_attributes_pairs_size, data.extra_attributes);
    if (!validation_result.success)
      return validation_result;
  }

  size_t thread_ctx_pairs_size = 0;
  if (data.thread_ctx_config != NULL) {
    if (data.thread_ctx_config->schema_version != NULL) {
      const char *thread_ctx_pairs[] = {"threadlocal.schema_version",
                                        data.thread_ctx_config->schema_version,
                                        NULL};
      validation_result = validate_and_calculate_protobuf_payload_size(
          &thread_ctx_pairs_size, thread_ctx_pairs);
      if (!validation_result.success)
        return validation_result;
    }
    if (data.thread_ctx_config->attribute_key_map != NULL) {
      if (data.thread_ctx_config->schema_version == NULL) {
        return (otel_process_ctx_result){
            .success = false,
            .error_message =
                "attribute_key_map requires schema_version to be set (" __FILE__
                ":" ADD_QUOTES(__LINE__) ")"};
      }
      for (size_t i = 0; data.thread_ctx_config->attribute_key_map[i] != NULL;
           i++) {
        if (strlen(data.thread_ctx_config->attribute_key_map[i]) >
            KEY_VALUE_LIMIT) {
          return (otel_process_ctx_result){
              .success = false,
              .error_message = "Length of attribute_key_map entry exceeds 4096 "
                               "limit (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
        }
      }
      size_t array_value_content_size = protobuf_otel_array_value_content_size(
          data.thread_ctx_config->attribute_key_map);
      size_t any_value_content_size =
          protobuf_record_size(array_value_content_size);
      size_t kv_content_size =
          protobuf_string_size("threadlocal.attribute_key_map") +
          protobuf_record_size(any_value_content_size);
      thread_ctx_pairs_size += protobuf_record_size(kv_content_size);
    }
  }

  size_t resource_size = pairs_size + resource_attributes_pairs_size;
  size_t total_size = protobuf_record_size(resource_size) +
                      extra_attributes_pairs_size + thread_ctx_pairs_size;

  char *encoded = (char *)calloc(total_size, 1);
  if (!encoded) {
    return (otel_process_ctx_result){
        .success = false,
        .error_message = "Failed to allocate memory for payload (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")"};
  }
  char *ptr = encoded;

  // ProcessContext.resource (field 1)
  write_protobuf_tag(&ptr, 1);
  write_protobuf_varint(&ptr, resource_size);

  for (size_t i = 0; pairs[i * 2] != NULL; i++) {
    write_attribute(&ptr, 1, pairs[i * 2], pairs[i * 2 + 1]);
  }

  for (size_t i = 0; data.resource_attributes != NULL &&
                     data.resource_attributes[i * 2] != NULL;
       i++) {
    write_attribute(&ptr, 1, data.resource_attributes[i * 2],
                    data.resource_attributes[i * 2 + 1]);
  }

  // ProcessContext.extra_attributes (field 2)
  for (size_t i = 0;
       data.extra_attributes != NULL && data.extra_attributes[i * 2] != NULL;
       i++) {
    write_attribute(&ptr, 2, data.extra_attributes[i * 2],
                    data.extra_attributes[i * 2 + 1]);
  }

  if (data.thread_ctx_config != NULL) {
    if (data.thread_ctx_config->schema_version != NULL) {
      write_attribute(&ptr, 2, "threadlocal.schema_version",
                      data.thread_ctx_config->schema_version);
    }
    if (data.thread_ctx_config->attribute_key_map != NULL) {
      write_array_attribute(&ptr, 2, "threadlocal.attribute_key_map",
                            data.thread_ctx_config->attribute_key_map);
    }
  }

  *out = encoded;
  *out_size = (uint32_t)total_size;

  return (otel_process_ctx_result){.success = true, .error_message = NULL};
}

#ifndef OTEL_PROCESS_CTX_NO_READ
#include <inttypes.h>
#include <limits.h>
#include <sys/uio.h>
#include <sys/utsname.h>

// Note: The below parsing code is only for otel_process_ctx_read and is only
// provided for debugging and testing purposes.

static void *parse_mapping_start(char *line) {
  char *endptr = NULL;
  unsigned long long start = strtoull(line, &endptr, 16);
  if (start == 0 || start == ULLONG_MAX)
    return NULL;
  return (void *)(uintptr_t)start;
}

static otel_process_ctx_mapping *try_finding_mapping(void) {
  char line[8192];
  otel_process_ctx_mapping *result = NULL;

  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp)
    return result;

  while (fgets(line, sizeof(line), fp)) {
    bool is_process_ctx = strstr(line, "[anon_shmem:OTEL_CTX]") != NULL ||
                          strstr(line, "[anon:OTEL_CTX]") != NULL ||
                          strstr(line, "/memfd:OTEL_CTX") != NULL;
    if (is_process_ctx) {
      result = (otel_process_ctx_mapping *)parse_mapping_start(line);
      break;
    }
  }

  fclose(fp);
  return result;
}

// Helper function to read a protobuf varint (limited to 1-2 bytes, max value
// UINT14_MAX, matching write_protobuf_varint above)
static bool read_protobuf_varint(char **ptr, char *end_ptr, uint16_t *value) {
  if (*ptr >= end_ptr)
    return false;

  unsigned char first_byte = (unsigned char)**ptr;
  (*ptr)++;

  if (first_byte < 128) {
    *value = first_byte;
    return true;
  } else {
    if (*ptr >= end_ptr)
      return false;
    unsigned char second_byte = (unsigned char)**ptr;
    (*ptr)++;

    *value = (first_byte & 0x7F) | (second_byte << 7);
    return *value <= UINT14_MAX;
  }
}

// Helper function to read a protobuf string into a buffer, within the same
// limits as the encoder imposes
static bool read_protobuf_string(char **ptr, char *end_ptr, char *buffer) {
  uint16_t len;
  if (!read_protobuf_varint(ptr, end_ptr, &len) || len >= KEY_VALUE_LIMIT + 1 ||
      *ptr + len > end_ptr)
    return false;

  memcpy(buffer, *ptr, len);
  buffer[len] = '\0';
  *ptr += len;

  return true;
}

// Reads field name and validates the fixed LEN wire type
static bool read_protobuf_tag(char **ptr, char *end_ptr,
                              uint8_t *field_number) {
  if (*ptr >= end_ptr)
    return false;

  unsigned char tag = (unsigned char)**ptr;
  (*ptr)++;

  uint8_t wire_type = tag & 0x07;
  *field_number = tag >> 3;

  return wire_type == 2; // We only need the LEN wire type for now
}

// Peeks at the key of an OTel KeyValue message without advancing the pointer.
static bool peek_protobuf_key(char *ptr, char *end_ptr, char *key_buffer) {
  char *p = ptr;
  uint8_t kv_field;
  if (!read_protobuf_tag(&p, end_ptr, &kv_field))
    return false;
  if (kv_field != 1)
    return false; // KeyValue.key is field 1
  return read_protobuf_string(&p, end_ptr, key_buffer);
}

// Reads an OTel KeyValue message (key string + AnyValue-wrapped string) into
// the provided buffers.
static bool read_protobuf_keyvalue(char **ptr, char *end_ptr, char *key_buffer,
                                   char *value_buffer) {
  bool key_found = false;
  bool value_found = false;

  while (*ptr < end_ptr) {
    uint8_t kv_field;
    if (!read_protobuf_tag(ptr, end_ptr, &kv_field))
      return false;

    if (kv_field == 1) { // KeyValue.key
      if (!read_protobuf_string(ptr, end_ptr, key_buffer))
        return false;
      key_found = true;
    } else if (kv_field == 2) { // KeyValue.value (AnyValue)
      uint16_t _any_len; // Unused, but we still need to consume + validate the
                         // varint
      if (!read_protobuf_varint(ptr, end_ptr, &_any_len))
        return false;
      uint8_t any_field;
      if (!read_protobuf_tag(ptr, end_ptr, &any_field))
        return false;

      if (any_field == 1) { // AnyValue.string_value
        if (!read_protobuf_string(ptr, end_ptr, value_buffer))
          return false;
        value_found = true;
      }
    }
  }

  return key_found && value_found;
}

// Reads an AnyValue.array_value (field 5) from ptr; ptr must be at
// KeyValue.value (tag 2). Allocates a NULL-terminated array of strings and sets
// *out_array immediately. On error the caller must free it.
static bool read_protobuf_array_value_strings(char **ptr, char *end_ptr,
                                              char *value_buffer,
                                              const char ***out_array) {
  uint8_t field;
  if (!read_protobuf_tag(ptr, end_ptr, &field) || field != 2)
    return false;
  uint16_t any_len;
  if (!read_protobuf_varint(ptr, end_ptr, &any_len))
    return false;
  char *any_end = *ptr + any_len;
  if (any_end > end_ptr)
    return false;

  if (!read_protobuf_tag(ptr, any_end, &field) || field != 5)
    return false;
  uint16_t array_len;
  if (!read_protobuf_varint(ptr, any_end, &array_len))
    return false;
  char *array_end = *ptr + array_len;
  if (array_end > any_end)
    return false;

  size_t max = 100;
  size_t capacity = max + 1;
  const char **arr = (const char **)calloc(capacity, sizeof(char *));
  if (!arr)
    return false;
  *out_array = arr;
  size_t count = 0;

  while (*ptr < array_end) {
    if (count >= max)
      return false;
    if (!read_protobuf_tag(ptr, array_end, &field) || field != 1)
      return false;
    uint16_t item_len;
    if (!read_protobuf_varint(ptr, array_end, &item_len))
      return false;
    char *item_end = *ptr + item_len;
    if (item_end > array_end)
      return false;
    if (!read_protobuf_tag(ptr, item_end, &field) || field != 1)
      return false;
    if (!read_protobuf_string(ptr, item_end, value_buffer))
      return false;
    char *dup = strdup(value_buffer);
    if (!dup)
      return false;
    arr[count++] = dup;
  }

  return true;
}

// Simplified protobuf decoder to match the exact encoder above. If the protobuf
// data doesn't match the encoder, this will return false.
static bool otel_process_ctx_decode_payload(char *payload,
                                            uint32_t payload_size,
                                            otel_process_ctx_data *data_out,
                                            char *key_buffer,
                                            char *value_buffer) {
  char *ptr = payload;
  char *end_ptr = payload + payload_size;

  *data_out = empty_data;

  // Parse ProcessContext wrapper - expect field 1 (resource)
  uint8_t process_ctx_field;
  if (!read_protobuf_tag(&ptr, end_ptr, &process_ctx_field) ||
      process_ctx_field != 1)
    return false;

  uint16_t resource_len;
  if (!read_protobuf_varint(&ptr, end_ptr, &resource_len))
    return false;
  char *resource_end = ptr + resource_len;
  if (resource_end > end_ptr)
    return false;

  size_t resource_index = 0;
  size_t resource_capacity =
      201; // Allocate space for 100 pairs + NULL terminator entry
  data_out->resource_attributes =
      (const char **)calloc(resource_capacity, sizeof(char *));
  if (data_out->resource_attributes == NULL)
    return false;

  size_t extra_attributes_index = 0;
  size_t extra_attributes_capacity =
      201; // Allocate space for 100 pairs + NULL terminator entry
  data_out->extra_attributes =
      (const char **)calloc(extra_attributes_capacity, sizeof(char *));
  if (data_out->extra_attributes == NULL)
    return false;

  // Parse resource attributes (field 1)
  while (ptr < resource_end) {
    uint8_t field_number;
    if (!read_protobuf_tag(&ptr, resource_end, &field_number) ||
        field_number != 1)
      return false;

    uint16_t kv_len;
    if (!read_protobuf_varint(&ptr, resource_end, &kv_len))
      return false;
    char *kv_end = ptr + kv_len;
    if (kv_end > resource_end)
      return false;

    if (!read_protobuf_keyvalue(&ptr, kv_end, key_buffer, value_buffer))
      return false;

    char *value = strdup(value_buffer);
    if (!value)
      return false;

    // Dispatch based on key
    const char **field = NULL;
    if (strcmp(key_buffer, "deployment.environment.name") == 0) {
      field = &data_out->deployment_environment_name;
    } else if (strcmp(key_buffer, "service.instance.id") == 0) {
      field = &data_out->service_instance_id;
    } else if (strcmp(key_buffer, "service.name") == 0) {
      field = &data_out->service_name;
    } else if (strcmp(key_buffer, "service.version") == 0) {
      field = &data_out->service_version;
    } else if (strcmp(key_buffer, "telemetry.sdk.language") == 0) {
      field = &data_out->telemetry_sdk_language;
    } else if (strcmp(key_buffer, "telemetry.sdk.version") == 0) {
      field = &data_out->telemetry_sdk_version;
    } else if (strcmp(key_buffer, "telemetry.sdk.name") == 0) {
      field = &data_out->telemetry_sdk_name;
    }

    if (field != NULL) {
      if (*field != NULL) {
        free(value);
        return false;
      }
      *field = value;
    } else {
      char *key = strdup(key_buffer);

      if (!key || resource_index + 2 >= resource_capacity) {
        free(key);
        free(value);
        return false;
      }
      data_out->resource_attributes[resource_index] = key;
      data_out->resource_attributes[resource_index + 1] = value;
      resource_index += 2;
    }
  }

  // Parse extra attributes (field 2)
  while (ptr < end_ptr) {
    uint8_t extra_ctx_field;
    if (!read_protobuf_tag(&ptr, end_ptr, &extra_ctx_field) ||
        extra_ctx_field != 2)
      return false;

    uint16_t kv_len;
    if (!read_protobuf_varint(&ptr, end_ptr, &kv_len))
      return false;
    char *kv_end = ptr + kv_len;
    if (kv_end > end_ptr)
      return false;

    if (!peek_protobuf_key(ptr, kv_end, key_buffer))
      return false;

    if (strcmp(key_buffer, "threadlocal.attribute_key_map") == 0) {
      // Consume key to advance ptr
      uint8_t kv_field;
      if (!read_protobuf_tag(&ptr, kv_end, &kv_field) || kv_field != 1)
        return false;
      if (!read_protobuf_string(&ptr, kv_end, key_buffer))
        return false;
      if (!data_out->thread_ctx_config) {
        otel_thread_ctx_config_data *setup =
            (otel_thread_ctx_config_data *)calloc(
                1, sizeof(otel_thread_ctx_config_data));
        if (!setup)
          return false;
        data_out->thread_ctx_config = setup;
      }
      if (!read_protobuf_array_value_strings(
              &ptr, kv_end, value_buffer,
              &((otel_thread_ctx_config_data *)data_out->thread_ctx_config)
                   ->attribute_key_map))
        return false;
    } else {
      if (!read_protobuf_keyvalue(&ptr, kv_end, key_buffer, value_buffer))
        return false;

      char *value = strdup(value_buffer);
      if (!value)
        return false;

      // Dispatch based on key
      if (strcmp(key_buffer, "threadlocal.schema_version") == 0) {
        otel_thread_ctx_config_data *setup =
            (otel_thread_ctx_config_data *)calloc(
                1, sizeof(otel_thread_ctx_config_data));
        if (!setup) {
          free(value);
          return false;
        }
        setup->schema_version = value;
        data_out->thread_ctx_config = setup;
      } else {
        char *key = strdup(key_buffer);
        if (!key || extra_attributes_index + 2 >= extra_attributes_capacity) {
          free(key);
          free(value);
          return false;
        }
        data_out->extra_attributes[extra_attributes_index] = key;
        data_out->extra_attributes[extra_attributes_index + 1] = value;
        extra_attributes_index += 2;
      }
    }
  }

  // Validate all required fields were found
  return data_out->deployment_environment_name != NULL &&
         data_out->service_instance_id != NULL &&
         data_out->service_name != NULL && data_out->service_version != NULL &&
         data_out->telemetry_sdk_language != NULL &&
         data_out->telemetry_sdk_version != NULL &&
         data_out->telemetry_sdk_name != NULL;
}

void otel_process_ctx_read_data_drop(otel_process_ctx_data data) {
  if (data.deployment_environment_name)
    free((void *)data.deployment_environment_name);
  if (data.service_instance_id)
    free((void *)data.service_instance_id);
  if (data.service_name)
    free((void *)data.service_name);
  if (data.service_version)
    free((void *)data.service_version);
  if (data.telemetry_sdk_language)
    free((void *)data.telemetry_sdk_language);
  if (data.telemetry_sdk_version)
    free((void *)data.telemetry_sdk_version);
  if (data.telemetry_sdk_name)
    free((void *)data.telemetry_sdk_name);
  if (data.resource_attributes) {
    for (int i = 0; data.resource_attributes[i] != NULL; i++)
      free((void *)data.resource_attributes[i]);
    free((void *)data.resource_attributes);
  }
  if (data.extra_attributes) {
    for (int i = 0; data.extra_attributes[i] != NULL; i++)
      free((void *)data.extra_attributes[i]);
    free((void *)data.extra_attributes);
  }
  if (data.thread_ctx_config) {
    if (data.thread_ctx_config->schema_version)
      free((void *)data.thread_ctx_config->schema_version);
    if (data.thread_ctx_config->attribute_key_map) {
      for (int i = 0; data.thread_ctx_config->attribute_key_map[i] != NULL;
           i++) {
        free((void *)data.thread_ctx_config->attribute_key_map[i]);
      }
      free((void *)data.thread_ctx_config->attribute_key_map);
    }
    free((void *)data.thread_ctx_config);
  }
}

otel_process_ctx_read_result otel_process_ctx_read(void) {
  otel_process_ctx_mapping *mapping = try_finding_mapping();
  if (!mapping) {
    return (otel_process_ctx_read_result){
        .success = false,
        .error_message =
            "No OTEL_CTX mapping found (" __FILE__ ":" ADD_QUOTES(__LINE__) ")",
        .data = empty_data};
  }

  if (strncmp(mapping->otel_process_ctx_signature, OTEL_CTX_SIGNATURE,
              sizeof(mapping->otel_process_ctx_signature)) != 0 ||
      mapping->otel_process_ctx_version != 2) {
    return (otel_process_ctx_read_result){
        .success = false,
        .error_message = "Invalid OTEL_CTX signature or version (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")",
        .data = empty_data};
  }

  otel_process_ctx_data data = empty_data;

  char *key_buffer = (char *)calloc(KEY_VALUE_LIMIT + 1, 1);
  char *value_buffer = (char *)calloc(KEY_VALUE_LIMIT + 1, 1);
  if (!key_buffer || !value_buffer) {
    free(key_buffer);
    free(value_buffer);
    return (otel_process_ctx_read_result){
        .success = false,
        .error_message = "Failed to allocate decode buffers (" __FILE__
                         ":" ADD_QUOTES(__LINE__) ")",
        .data = empty_data};
  }

  bool success = otel_process_ctx_decode_payload(
      mapping->otel_process_payload, mapping->otel_process_payload_size, &data,
      key_buffer, value_buffer);
  free(key_buffer);
  free(value_buffer);

  if (!success) {
    otel_process_ctx_read_data_drop(data);
    return (otel_process_ctx_read_result){
        .success = false,
        .error_message =
            "Failed to decode payload (" __FILE__ ":" ADD_QUOTES(__LINE__) ")",
        .data = empty_data};
  }

  return (otel_process_ctx_read_result){
      .success = true, .error_message = NULL, .data = data};
}

bool otel_process_ctx_read_drop(otel_process_ctx_read_result *result) {
  if (!result || !result->success)
    return false;
  otel_process_ctx_read_data_drop(result->data);
  *result = (otel_process_ctx_read_result){
      .success = false, .error_message = "Data dropped", .data = empty_data};
  return true;
}
#endif // OTEL_PROCESS_CTX_NO_READ

#endif // OTEL_PROCESS_CTX_NOOP
