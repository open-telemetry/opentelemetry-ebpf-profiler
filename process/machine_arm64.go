//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import "debug/elf"

const currentMachine = elf.EM_AARCH64
