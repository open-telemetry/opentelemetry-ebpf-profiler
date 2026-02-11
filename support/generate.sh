#!/usr/bin/env bash

set -eu

# Generate support/types.go
echo "Generating support/types.go..."

# Put license header at the top of the file
cat <<EOF >types_gen.go
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

EOF

# Generate Go definitions from C
go tool cgo -godefs types_def.go >> types_gen.go

# Properly format the generated code
go fmt .

# Set correct package path
sed -i 's/^package support$/package support \/\/ import "go.opentelemetry.io\/ebpf-profiler\/support"/' types_gen.go

if ! diff types_gen.go types.go; then
    echo "Auto generated and existing code differ, please review and update support/types.go"
    exit 1
fi

# Clean up temporary files
rm -rf _obj/ types_gen.go

# Generate support/usdt/types.go
echo "Generating support/usdt/types.go..."

cd usdt

# Generate types_gen.go without license (cgo adds its own header)
go tool cgo -godefs types_def.go > types_gen.go

# Properly format the generated code
go fmt .

if ! diff types_gen.go types.go; then
    echo "Auto generated and existing code differ, please review and update support/usdt/types.go"
    exit 1
fi

# Clean up temporary files
rm -rf _obj/ types_gen.go

cd ..

echo "All type definitions are up to date"
