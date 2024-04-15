/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64

#ifndef __FSBASE_DECODE_X86_64__
#define __FSBASE_DECODE_X86_64__

#include <stdint.h>

uint32_t decode_fsbase_aout_dump_debugregs(const uint8_t* code, size_t codesz);

#endif
