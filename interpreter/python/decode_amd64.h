// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

#ifndef __PYTHON_DECODE_X86_64__
#define __PYTHON_DECODE_X86_64__

#include <stdint.h>

uint64_t decode_stub_argument(const uint8_t* code, size_t code_sz, uint64_t code_address, uint64_t memory_base);

#endif
