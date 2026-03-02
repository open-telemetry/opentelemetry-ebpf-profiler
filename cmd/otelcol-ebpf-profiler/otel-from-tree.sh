#!/usr/bin/env bash

set -euo pipefail

echo "Adding local opentelemetry-collector replaces to manifest.yaml"

if grep -q "# START otel-from-tree" cmd/otelcol-ebpf-profiler/manifest.yaml; then
    echo "otel-from-tree already applied. Run 'make otel-from-lib' first to revert."
    exit 1
fi

echo "  # START otel-from-tree - Do not edit below this line" >> cmd/otelcol-ebpf-profiler/manifest.yaml

grep -E "gomod: go.opentelemetry.io/collector/" cmd/otelcol-ebpf-profiler/manifest.yaml | \
    sed -E 's/.*gomod: ([^ ]+) .*/\1/' | \
    sort -u | \
    while read -r module; do
        subpath=${module#go.opentelemetry.io/collector}
        echo "  - ${module} => ../opentelemetry-collector${subpath}" >> cmd/otelcol-ebpf-profiler/manifest.yaml
    done

echo "Local replaces added. You can now build with local opentelemetry-collector changes."
