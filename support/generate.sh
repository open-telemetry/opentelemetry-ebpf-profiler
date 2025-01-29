#!/usr/bin/env bash

set -eu

# Put license header at the top of the file
echo "// Copyright The OpenTelemetry Authors" > types_gen.go
echo "// SPDX-License-Identifier: Apache-2.0" >> types_gen.go
echo "" >> types_gen.go

# Generate Go definitions from C
go tool cgo -godefs types_def.go >> types_gen.go

# Set correct package path
sed -i 's/^package support$/package support \/\/ import "go.opentelemetry.io\/ebpf-profiler\/support"/' types_gen.go

if ! diff types_gen.go types.go; then
    echo "Auto generated and existing code differ"
    exit 1
fi

# Clean up temporary files
rm -rf _obj/ types_gen.go
