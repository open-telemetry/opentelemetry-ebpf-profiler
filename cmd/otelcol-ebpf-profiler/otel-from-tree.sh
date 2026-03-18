#!/usr/bin/env bash

# NOTE: This script needs to be executed from the root directory
# of the repository.

set -euo pipefail

# Use COLLECTOR_PATH if set, otherwise default to ../../../opentelemetry-collector
COLLECTOR_PATH="${COLLECTOR_PATH:-../../../opentelemetry-collector}"

echo "Adding local opentelemetry-collector replaces to manifest.yaml"
echo "Using collector path: $COLLECTOR_PATH"

if grep -q "# START otel-from-tree" cmd/otelcol-ebpf-profiler/manifest.yaml; then
    echo "otel-from-tree already applied. Run 'make otel-from-lib' first to revert."
    exit 1
fi

echo "  # START otel-from-tree - Do not edit below this line" >> cmd/otelcol-ebpf-profiler/manifest.yaml

# Replace collector module dependencies with local paths
cd cmd/otelcol-ebpf-profiler && go list -m -u all | \
    grep 'go\.opentelemetry\.io/collector' | \
    awk '{print $1}' | \
  while read -r module; do
    echo "$module"
    subpath=${module#go.opentelemetry.io/collector}
    echo "  - ${module} => ${COLLECTOR_PATH}${subpath}" >> manifest.yaml
  done

echo "Local replaces added. You can now build with local opentelemetry-collector changes."
