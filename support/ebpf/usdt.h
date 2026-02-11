// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef OPTI_USDT_H
#define OPTI_USDT_H

#include "types.h"

// USDT argument specification structures
enum bpf_usdt_arg_type {
  BPF_USDT_ARG_CONST,
  BPF_USDT_ARG_REG,
  BPF_USDT_ARG_REG_DEREF,
};

// Register IDs
enum bpf_usdt_register {
  BPF_USDT_REG_NONE = 0,

  // x86_64 registers (1-17)
  BPF_USDT_REG_RAX = 1,
  BPF_USDT_REG_RBX = 2,
  BPF_USDT_REG_RCX = 3,
  BPF_USDT_REG_RDX = 4,
  BPF_USDT_REG_RSI = 5,
  BPF_USDT_REG_RDI = 6,
  BPF_USDT_REG_RBP = 7,
  BPF_USDT_REG_RSP = 8,
  BPF_USDT_REG_R8  = 9,
  BPF_USDT_REG_R9  = 10,
  BPF_USDT_REG_R10 = 11,
  BPF_USDT_REG_R11 = 12,
  BPF_USDT_REG_R12 = 13,
  BPF_USDT_REG_R13 = 14,
  BPF_USDT_REG_R14 = 15,
  BPF_USDT_REG_R15 = 16,
  BPF_USDT_REG_RIP = 17,

  // ARM64 registers (32-64)
  BPF_USDT_REG_X0  = 32,
  BPF_USDT_REG_X1  = 33,
  BPF_USDT_REG_X2  = 34,
  BPF_USDT_REG_X3  = 35,
  BPF_USDT_REG_X4  = 36,
  BPF_USDT_REG_X5  = 37,
  BPF_USDT_REG_X6  = 38,
  BPF_USDT_REG_X7  = 39,
  BPF_USDT_REG_X8  = 40,
  BPF_USDT_REG_X9  = 41,
  BPF_USDT_REG_X10 = 42,
  BPF_USDT_REG_X11 = 43,
  BPF_USDT_REG_X12 = 44,
  BPF_USDT_REG_X13 = 45,
  BPF_USDT_REG_X14 = 46,
  BPF_USDT_REG_X15 = 47,
  BPF_USDT_REG_X16 = 48,
  BPF_USDT_REG_X17 = 49,
  BPF_USDT_REG_X18 = 50,
  BPF_USDT_REG_X19 = 51,
  BPF_USDT_REG_X20 = 52,
  BPF_USDT_REG_X21 = 53,
  BPF_USDT_REG_X22 = 54,
  BPF_USDT_REG_X23 = 55,
  BPF_USDT_REG_X24 = 56,
  BPF_USDT_REG_X25 = 57,
  BPF_USDT_REG_X26 = 58,
  BPF_USDT_REG_X27 = 59,
  BPF_USDT_REG_X28 = 60,
  BPF_USDT_REG_X29 = 61, // FP
  BPF_USDT_REG_X30 = 62, // LR
  BPF_USDT_REG_SP  = 63,
  BPF_USDT_REG_PC  = 64,
};

// USDT argument specification structures
#define BPF_USDT_MAX_ARG_CNT 12

struct bpf_usdt_arg_spec {
  u64 val_off;       // Constant value OR memory offset from register
  u32 arg_type;      // CONST, REG, or REG_DEREF (enum bpf_usdt_arg_type)
  u8 reg_id;         // Register ID (enum bpf_usdt_register)
  bool arg_signed;   // Whether argument is signed
  s8 arg_bitshift;   // Bits to shift for size adjustment (64 - arg_sz*8)
  bool arg_is_float; // Whether argument is floating-point
  u8 _pad[1];        // Padding for alignment
};

struct bpf_usdt_spec {
  struct bpf_usdt_arg_spec args[BPF_USDT_MAX_ARG_CNT];
  u64 usdt_cookie;
  s16 arg_cnt;
  u8 _pad[6]; // Padding for alignment
};

#endif // OPTI_USDT_H
