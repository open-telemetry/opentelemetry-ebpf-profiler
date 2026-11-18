// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Makes record reachable through otel_thread_ctx_nodejs_v1 for the calling
// thread.
void nodectx_publish(void *record);
