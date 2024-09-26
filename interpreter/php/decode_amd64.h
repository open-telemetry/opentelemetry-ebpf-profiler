// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64
#ifndef __INCLUDED_PHP_DECODE_X86_64__
#define __INCLUDED_PHP_DECODE_X86_64__
#include <stdint.h>
#include <stddef.h>

// Note: to make it easier to convert C error codes into Go error strings
// we place an enum here that represents the set of allowed
// error codes. These represent the errors that could
// occur during the execution of each function.
enum x86PHPJITDecodingCodes {
  // No error: happens when no error happens.
  NO_ERROR = 0,
  // Happens when we iterate over the whole blob
  // without finding the target instruction
  NOT_FOUND_ERROR = 1,
  // Happens when we encounter a CALL/JMP before finding
  // the target instruction
  EARLY_RETURN_ERROR = 2,
  // Happens when we fail to decode due to a small blob.
  DECODING_ERROR = 3,
};

int retrieveExecuteExJumpLabelAddress(const uint8_t * const code, const size_t codesize,
                                      const uint64_t rip_base, uint64_t * const out);
int retrieveZendVMKind(const uint8_t * const code, const size_t codesize, uint64_t * const out);
int retrieveJITBufferPtr(const uint8_t * const code, const size_t codesize,
                         const uint64_t rip_base, uint64_t * const buffer_ptr,
                         uint64_t * const size_ptr);
#endif
