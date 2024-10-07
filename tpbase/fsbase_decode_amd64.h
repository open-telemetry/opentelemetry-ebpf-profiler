// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

#ifndef __FSBASE_DECODE_X86_64__
#define __FSBASE_DECODE_X86_64__

#include <stdint.h>

uint32_t decode_fsbase_aout_dump_debugregs(const uint8_t* code, size_t codesz);

#endif
