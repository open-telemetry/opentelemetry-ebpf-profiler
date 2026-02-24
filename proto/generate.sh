#!/usr/bin/env bash

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -eu

# This script generates Go code from the ProcessContext protobuf definition.
# It requires protoc and protoc-gen-go to be installed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Create temporary directory for OpenTelemetry proto definitions
OTEL_PROTO_DIR="$(mktemp -d)"
trap "rm -rf '${OTEL_PROTO_DIR}'" EXIT

echo "Cloning OpenTelemetry proto definitions to temporary directory..."
git clone --depth 1 --branch v1.9.0 \
    https://github.com/open-telemetry/opentelemetry-proto.git \
    "${OTEL_PROTO_DIR}" 2>/dev/null

# Generate Go code
echo -n "Generating ProcessContext protobuf code..."
cd "${REPO_ROOT}"

protoc \
    --go_out=. \
    --go_opt=paths=source_relative \
    --go_opt=Mopentelemetry/proto/resource/v1/resource.proto=go.opentelemetry.io/proto/slim/otlp/resource/v1 \
    --go_opt=Mopentelemetry/proto/common/v1/common.proto=go.opentelemetry.io/proto/slim/otlp/common/v1 \
    --proto_path="${OTEL_PROTO_DIR}" \
    --proto_path=. \
    proto/processcontext/processcontext.proto

echo " done"
