/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64

#ifndef __PYTHON_DECODE_X86_64__
#define __PYTHON_DECODE_X86_64__

#include <stdint.h>

uint64_t decode_stub_argument(const uint8_t* code, size_t codesz, uint8_t argument_no, uint64_t rip_base, uint64_t memory_base);

#endif
