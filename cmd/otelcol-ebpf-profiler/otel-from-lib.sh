#!/usr/bin/env bash

set -euo pipefail

echo "Removing local opentelemetry-collector replaces from manifest.yaml"

if ! grep -q "# START otel-from-tree" cmd/otelcol-ebpf-profiler/manifest.yaml; then
    echo "otel-from-tree not currently applied. Nothing to revert."
    exit 0
fi

sed -i '/# START otel-from-tree/,$d' cmd/otelcol-ebpf-profiler/manifest.yaml
echo "Local replaces removed. Collector will use published opentelemetry-collector modules."
