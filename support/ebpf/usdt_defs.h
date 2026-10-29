// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#define USDT_MAX_ARGUMENTS 12

enum USDTArgumentKind {
  USDT_ARGUMENT_CONSTANT,
  USDT_ARGUMENT_REGISTER,
  USDT_ARGUMENT_REGISTER_DEREFERENCE,
};

// Byte offsets within the Linux user register ABI. They are exposed to Go by
// support/types_def.go and checked against the pt_regs definition selected by
// each eBPF target below.
enum {
  USDT_AMD64_PT_REGS_R15_OFFSET = 0 * sizeof(u64),
  USDT_AMD64_PT_REGS_R14_OFFSET = 1 * sizeof(u64),
  USDT_AMD64_PT_REGS_R13_OFFSET = 2 * sizeof(u64),
  USDT_AMD64_PT_REGS_R12_OFFSET = 3 * sizeof(u64),
  USDT_AMD64_PT_REGS_RBP_OFFSET = 4 * sizeof(u64),
  USDT_AMD64_PT_REGS_RBX_OFFSET = 5 * sizeof(u64),
  USDT_AMD64_PT_REGS_R11_OFFSET = 6 * sizeof(u64),
  USDT_AMD64_PT_REGS_R10_OFFSET = 7 * sizeof(u64),
  USDT_AMD64_PT_REGS_R9_OFFSET  = 8 * sizeof(u64),
  USDT_AMD64_PT_REGS_R8_OFFSET  = 9 * sizeof(u64),
  USDT_AMD64_PT_REGS_RAX_OFFSET = 10 * sizeof(u64),
  USDT_AMD64_PT_REGS_RCX_OFFSET = 11 * sizeof(u64),
  USDT_AMD64_PT_REGS_RDX_OFFSET = 12 * sizeof(u64),
  USDT_AMD64_PT_REGS_RSI_OFFSET = 13 * sizeof(u64),
  USDT_AMD64_PT_REGS_RDI_OFFSET = 14 * sizeof(u64),
  USDT_AMD64_PT_REGS_RIP_OFFSET = 16 * sizeof(u64),
  USDT_AMD64_PT_REGS_RSP_OFFSET = 19 * sizeof(u64),

  USDT_ARM64_PT_REGS_X0_OFFSET     = 0 * sizeof(u64),
  USDT_ARM64_PT_REGS_REGISTER_SIZE = sizeof(u64),
  USDT_ARM64_PT_REGS_SP_OFFSET     = 31 * sizeof(u64),
  USDT_ARM64_PT_REGS_PC_OFFSET     = 32 * sizeof(u64),
};

#if defined(__x86_64__)
  #define USDT_ASSERT_AMD64_OFFSET(name, field)                                                    \
    _Static_assert(                                                                                \
      USDT_AMD64_PT_REGS_##name##_OFFSET == __builtin_offsetof(struct pt_regs, field),             \
      "incorrect amd64 pt_regs offset for " #name)
USDT_ASSERT_AMD64_OFFSET(RAX, ax);
USDT_ASSERT_AMD64_OFFSET(RBX, bx);
USDT_ASSERT_AMD64_OFFSET(RCX, cx);
USDT_ASSERT_AMD64_OFFSET(RDX, dx);
USDT_ASSERT_AMD64_OFFSET(RSI, si);
USDT_ASSERT_AMD64_OFFSET(RDI, di);
USDT_ASSERT_AMD64_OFFSET(RBP, bp);
USDT_ASSERT_AMD64_OFFSET(RSP, sp);
USDT_ASSERT_AMD64_OFFSET(R8, r8);
USDT_ASSERT_AMD64_OFFSET(R9, r9);
USDT_ASSERT_AMD64_OFFSET(R10, r10);
USDT_ASSERT_AMD64_OFFSET(R11, r11);
USDT_ASSERT_AMD64_OFFSET(R12, r12);
USDT_ASSERT_AMD64_OFFSET(R13, r13);
USDT_ASSERT_AMD64_OFFSET(R14, r14);
USDT_ASSERT_AMD64_OFFSET(R15, r15);
USDT_ASSERT_AMD64_OFFSET(RIP, ip);
  #undef USDT_ASSERT_AMD64_OFFSET
#elif defined(__aarch64__)
_Static_assert(
  USDT_ARM64_PT_REGS_X0_OFFSET == __builtin_offsetof(struct pt_regs, regs[0]),
  "incorrect arm64 pt_regs offset for X0");
_Static_assert(
  USDT_ARM64_PT_REGS_X0_OFFSET + 30 * USDT_ARM64_PT_REGS_REGISTER_SIZE ==
    __builtin_offsetof(struct pt_regs, regs[30]),
  "incorrect arm64 pt_regs offset for X30");
_Static_assert(
  USDT_ARM64_PT_REGS_SP_OFFSET == __builtin_offsetof(struct pt_regs, sp),
  "incorrect arm64 pt_regs offset for SP");
_Static_assert(
  USDT_ARM64_PT_REGS_PC_OFFSET == __builtin_offsetof(struct pt_regs, pc),
  "incorrect arm64 pt_regs offset for PC");
#endif

typedef struct USDTArgumentSpec {
  u64 value_offset;
  u16 register_offset;
  u8 kind;
  u8 _pad[5];
} USDTArgumentSpec;

typedef struct USDTSpec {
  USDTArgumentSpec arguments[USDT_MAX_ARGUMENTS];
  u8 argument_count;
  u8 _pad[7];
} USDTSpec;

typedef struct USDTSpecKey {
  u32 pid;
  u32 _pad;
  u64 virtual_address;
} USDTSpecKey;

_Static_assert(sizeof(USDTArgumentSpec) == 16, "unexpected USDTArgumentSpec layout");
_Static_assert(sizeof(USDTSpec) == 200, "unexpected USDTSpec layout");
_Static_assert(sizeof(USDTSpecKey) == 16, "unexpected USDTSpecKey layout");
