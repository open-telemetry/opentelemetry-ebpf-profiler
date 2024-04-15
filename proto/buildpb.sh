#!/usr/bin/env bash

set -e

OUTDIR="experiments"

mkdir -p $OUTDIR

# OTel profiles signal
protoc --proto_path=. \
    --go_out=$OUTDIR --go_opt=paths=source_relative \
    opentelemetry/proto/profiles/v1/alternatives/pprofextended/pprofextended.proto

protoc --proto_path=. \
    --go_out=$OUTDIR --go_opt=paths=source_relative \
    opentelemetry/proto/profiles/v1/profiles.proto

# Manually fix import paths
sed -i 's/go.opentelemetry.io\/proto\/otlp\/profiles\/v1\/alternatives\/pprofextended/github.com\/elastic\/otel-profiling-agent\/proto\/experiments\/opentelemetry\/proto\/profiles\/v1\/alternatives\/pprofextended/' experiments/opentelemetry/proto/profiles/v1/profiles.pb.go

# OTel profiles service
protoc --proto_path=. \
    --go_out=$OUTDIR --go_opt=paths=source_relative \
    --go-grpc_out=$OUTDIR --go-grpc_opt=paths=source_relative \
    opentelemetry/proto/collector/profiles/v1/profiles_service.proto

# Manually fix import paths
sed -i 's/go.opentelemetry.io\/proto\/otlp\/profiles\/v1/github.com\/elastic\/otel-profiling-agent\/proto\/experiments\/opentelemetry\/proto\/profiles\/v1/' experiments/opentelemetry/proto/collector/profiles/v1/profiles_service.pb.go
