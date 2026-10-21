// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#define USDT_MAX_ARGUMENTS 12

enum USDTArgumentKind {
  USDT_ARGUMENT_CONSTANT,
  USDT_ARGUMENT_REGISTER,
  USDT_ARGUMENT_REGISTER_DEREFERENCE,
};

enum USDTRegister {
  USDT_REGISTER_NONE = 0,

  USDT_REGISTER_RAX = 1,
  USDT_REGISTER_RBX,
  USDT_REGISTER_RCX,
  USDT_REGISTER_RDX,
  USDT_REGISTER_RSI,
  USDT_REGISTER_RDI,
  USDT_REGISTER_RBP,
  USDT_REGISTER_RSP,
  USDT_REGISTER_R8,
  USDT_REGISTER_R9,
  USDT_REGISTER_R10,
  USDT_REGISTER_R11,
  USDT_REGISTER_R12,
  USDT_REGISTER_R13,
  USDT_REGISTER_R14,
  USDT_REGISTER_R15,
  USDT_REGISTER_RIP,

  // Numbered arm64 registers are contiguous and resolved relative to X0.
  USDT_REGISTER_X0  = 32,
  USDT_REGISTER_X30 = USDT_REGISTER_X0 + 30,
  USDT_REGISTER_SP  = USDT_REGISTER_X30 + 1,
  USDT_REGISTER_PC  = USDT_REGISTER_SP + 1,
};

typedef struct USDTArgumentSpec {
  u64 value_offset;
  u32 kind;
  u8 reg;
  u8 is_signed;
  s8 bit_shift;
  u8 is_float;
} USDTArgumentSpec;

typedef struct USDTSpec {
  USDTArgumentSpec arguments[USDT_MAX_ARGUMENTS];
  u8 argument_count;
  u8 _pad[7];
} USDTSpec;

typedef struct USDTSpecKey {
  u32 pid;
  u32 _pad;
  u64 file_id;
  u64 elf_address;
} USDTSpecKey;

_Static_assert(sizeof(USDTArgumentSpec) == 16, "unexpected USDTArgumentSpec layout");
_Static_assert(sizeof(USDTSpec) == 200, "unexpected USDTSpec layout");
_Static_assert(sizeof(USDTSpecKey) == 24, "unexpected USDTSpecKey layout");
