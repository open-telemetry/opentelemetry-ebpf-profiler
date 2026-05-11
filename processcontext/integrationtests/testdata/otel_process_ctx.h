// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License (Version 2.0). This product includes software
// developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog,
// Inc.

#pragma once

#define OTEL_PROCESS_CTX_VERSION_MAJOR 0
#define OTEL_PROCESS_CTX_VERSION_MINOR 1
#define OTEL_PROCESS_CTX_VERSION_PATCH 0
#define OTEL_PROCESS_CTX_VERSION_STRING "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/**
 * # OpenTelemetry Process Context reference implementation
 *
 * `otel_process_ctx.h` and `otel_process_ctx.c` provide a reference
 * implementation for the OpenTelemetry process-level context sharing
 * specification.
 * (https://github.com/open-telemetry/opentelemetry-specification/pull/4719/)
 *
 * This reference implementation is Linux-only, as the specification currently
 * only covers Linux. On non-Linux OS's (or when OTEL_PROCESS_CTX_NOOP is
 * defined) no-op versions of functions are supplied.
 */

/**
 * Config for the experimental thread context sharing mechanism, see
 * https://docs.google.com/document/d/1eatbHpEXXhWZEPrXZpfR58-5RIx-81mUgF69Zpn3Rz4/edit?tab=t.bmgoq3yor67o
 * for usage details.
 */
typedef struct {
  const char *schema_version;
  // NULL-terminated array of attribute key strings to be used in thread
  // context. Can be NULL if not needed.
  const char **attribute_key_map;
} otel_thread_ctx_config_data;

/**
 * Data that can be published as a process context.
 *
 * Every string MUST be valid for the duration of the call to
 * `otel_process_ctx_publish`. Strings will be copied into the context.
 *
 * Strings MUST be:
 * * Non-NULL
 * * UTF-8 encoded
 * * Not longer than INT16_MAX bytes
 *
 * Strings MAY be:
 * * Empty
 */
typedef struct {
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/deployment/#deployment-environment-name
  const char *deployment_environment_name;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/#service-instance-id
  const char *service_instance_id;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/#service-name
  const char *service_name;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/#service-version
  const char *service_version;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/telemetry/#telemetry-sdk-language
  const char *telemetry_sdk_language;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/telemetry/#telemetry-sdk-version
  const char *telemetry_sdk_version;
  // https://opentelemetry.io/docs/specs/semconv/registry/attributes/telemetry/#telemetry-sdk-name
  const char *telemetry_sdk_name;
  // Additional key/value pairs as resource attributes
  // https://opentelemetry.io/docs/specs/otel/resource/sdk/ Can be NULL if no
  // resource attributes are needed; if non-NULL, this array MUST be terminated
  // with a NULL entry. Every even entry is a key, every odd entry is a value
  // (E.g. "key1", "value1", "key2", "value2", NULL).
  const char **resource_attributes;
  // Additional key/value pairs as extra attributes
  // (ProcessContext.extra_attributes in process_context.proto) Can be NULL if
  // no extra attributes are needed; if non-NULL, this array MUST be terminated
  // with a NULL entry. Every even entry is a key, every odd entry is a value
  // (E.g. "key1", "value1", "key2", "value2", NULL).
  const char **extra_attributes;
  // Experimental thread context sharing mechanism configuration. See struct
  // definition for details. Can be NULL.
  const otel_thread_ctx_config_data *thread_ctx_config;
} otel_process_ctx_data;

/** Number of entries in the `otel_process_ctx_data` struct. Can be used to
 * easily detect when the struct is updated. */
#define OTEL_PROCESS_CTX_DATA_ENTRIES                                          \
  sizeof(otel_process_ctx_data) / sizeof(char *)

typedef struct {
  bool success;
  const char
      *error_message; // Static strings only, non-NULL if success is false
} otel_process_ctx_result;

/**
 * Publishes a OpenTelemetry process context with the given data.
 *
 * The context should remain alive until the application exits (or is just about
 * to exit). This method is NOT thread-safe.
 *
 * Calling `publish` multiple times is supported and will replace a previous
 * context (only one is published at any given time). Calling `publish` multiple
 * times usually happens when:
 * * Some of the `otel_process_ctx_data` changes due to a live system
 * reconfiguration for the same process
 * * The process is forked (to provide a new `service_instance_id`)
 *
 * This API can be called in a fork of the process that published the previous
 * context, even though the context is not carried over into forked processes
 * (although part of its memory allocations are).
 *
 * @param data Pointer to the data to publish. This data is copied into the
 * context and only needs to be valid for the duration of the call. Must not be
 * `NULL`.
 * @return The result of the operation.
 */
otel_process_ctx_result
otel_process_ctx_publish(const otel_process_ctx_data *data);

/**
 * Drops the current OpenTelemetry process context, if any.
 *
 * This method is safe to call even there's no current context.
 * This method is NOT thread-safe.
 *
 * This API can be called in a fork of the process that published the current
 * context to clean memory allocations related to the parent's context (even
 * though the context itself is not carried over into forked processes).
 *
 * @return `true` if the context was successfully dropped or no context existed,
 * `false` otherwise.
 */
bool otel_process_ctx_drop_current(void);

/** This can be disabled if no read support is required. */
#ifndef OTEL_PROCESS_CTX_NO_READ
typedef struct {
  bool success;
  const char
      *error_message; // Static strings only, non-NULL if success is false
  otel_process_ctx_data data; // Strings are allocated using `malloc` and the
                              // caller is responsible for `free`ing them
} otel_process_ctx_read_result;

/**
 * Reads the current OpenTelemetry process context, if any.
 *
 * Useful for debugging and testing purposes. Underlying returned strings in
 * `data` are dynamically allocated using `malloc` and
 * `otel_process_ctx_read_drop` must be called to free them.
 *
 * Thread-safety: This function assumes there is no concurrent mutation of the
 * process context.
 *
 * @return The result of the operation. If successful, `data` contains the
 * retrieved context data.
 */
otel_process_ctx_read_result otel_process_ctx_read(void);

/**
 * Drops the data resulting from a previous call to `otel_process_ctx_read`.
 *
 * @param result The result of a previous call to `otel_process_ctx_read`. Must
 * not be `NULL`.
 * @return `true` if the data was successfully dropped, `false` otherwise.
 */
bool otel_process_ctx_read_drop(otel_process_ctx_read_result *result);
#endif

#ifdef __cplusplus
}
#endif
