// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "bpfdefs.h"
#include "extmaps.h"
#include "types.h"
#include "usdt_defs.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
  #error "USDT argument decoding requires a little-endian target"
#endif

static inline EBPF_INLINE int usdt_register_offset(u8 reg)
{
#if defined(__x86_64__)
  // The x86 USDT register IDs do not follow the field order in pt_regs.
  // Keep the mapping explicit so every offset remains reviewable and constant.
  switch (reg) {
  case USDT_REGISTER_RAX: return __builtin_offsetof(struct pt_regs, ax);
  case USDT_REGISTER_RBX: return __builtin_offsetof(struct pt_regs, bx);
  case USDT_REGISTER_RCX: return __builtin_offsetof(struct pt_regs, cx);
  case USDT_REGISTER_RDX: return __builtin_offsetof(struct pt_regs, dx);
  case USDT_REGISTER_RSI: return __builtin_offsetof(struct pt_regs, si);
  case USDT_REGISTER_RDI: return __builtin_offsetof(struct pt_regs, di);
  case USDT_REGISTER_RBP: return __builtin_offsetof(struct pt_regs, bp);
  case USDT_REGISTER_RSP: return __builtin_offsetof(struct pt_regs, sp);
  case USDT_REGISTER_R8: return __builtin_offsetof(struct pt_regs, r8);
  case USDT_REGISTER_R9: return __builtin_offsetof(struct pt_regs, r9);
  case USDT_REGISTER_R10: return __builtin_offsetof(struct pt_regs, r10);
  case USDT_REGISTER_R11: return __builtin_offsetof(struct pt_regs, r11);
  case USDT_REGISTER_R12: return __builtin_offsetof(struct pt_regs, r12);
  case USDT_REGISTER_R13: return __builtin_offsetof(struct pt_regs, r13);
  case USDT_REGISTER_R14: return __builtin_offsetof(struct pt_regs, r14);
  case USDT_REGISTER_R15: return __builtin_offsetof(struct pt_regs, r15);
  case USDT_REGISTER_RIP: return __builtin_offsetof(struct pt_regs, ip);
  default: return -1;
  }
#elif defined(__aarch64__)
  // The arm64 X-register IDs and pt_regs.regs entries are both contiguous,
  // so their offsets can be derived directly instead of listed one by one.
  if (reg >= USDT_REGISTER_X0 && reg <= USDT_REGISTER_X30) {
    return (int)(__builtin_offsetof(struct pt_regs, regs[0]) +
                 (reg - USDT_REGISTER_X0) * sizeof(((struct pt_regs *)0)->regs[0]));
  }
  switch (reg) {
  case USDT_REGISTER_SP: return __builtin_offsetof(struct pt_regs, sp);
  case USDT_REGISTER_PC: return __builtin_offsetof(struct pt_regs, pc);
  default: return -1;
  }
#else
  #error "Unsupported architecture for USDT argument decoding"
#endif
}

static inline EBPF_INLINE long usdt_read_register(struct pt_regs *ctx, u8 reg, u64 *value)
{
  int offset = usdt_register_offset(reg);
  if (offset < 0) {
    return -1;
  }
  return bpf_probe_read_kernel(value, sizeof(*value), (void *)ctx + offset);
}

static inline EBPF_INLINE u64 usdt_probe_pc(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->ip;
#elif defined(__aarch64__)
  return ctx->pc;
#else
  #error "Unsupported architecture for USDT argument decoding"
#endif
}

// bpf_usdt_spec resolves the argument specification for the current USDT site.
// Callers may reuse the returned map value pointer until they invoke a helper
// that can mutate usdt_specs.
static inline EBPF_INLINE USDTSpec *bpf_usdt_spec(struct pt_regs *ctx, u32 pid)
{
  u64 pc = usdt_probe_pc(ctx);

  PIDPage mapping_key   = {};
  mapping_key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  mapping_key.pid       = __constant_cpu_to_be32(pid);
  mapping_key.page      = __constant_cpu_to_be64(pc);

  PIDPageMappingInfo *mapping = bpf_map_lookup_elem(&pid_page_to_mapping_info, &mapping_key);
  if (!mapping) {
    DEBUG_PRINT("usdt: mapping missing pid=%u pc=%lx", pid, pc);
    return NULL;
  }

  u64 bias = mapping->bias_and_unwind_program & 0x00FFFFFFFFFFFFFF;
  if (pc < bias) {
    DEBUG_PRINT("usdt: pc %lx is below bias %lx", pc, bias);
    return NULL;
  }

  USDTSpecKey spec_key = {
    .pid         = pid,
    .file_id     = mapping->file_id,
    .elf_address = pc - bias,
  };
  USDTSpec *spec = bpf_map_lookup_elem(&usdt_specs, &spec_key);
  if (!spec) {
    DEBUG_PRINT(
      "usdt: spec missing pid=%u file=%lx address=%lx",
      pid,
      spec_key.file_id,
      spec_key.elf_address);
    return NULL;
  }
  return spec;
}

// bpf_usdt_arg reads one argument from a specification returned by
// bpf_usdt_spec. It returns zero on success and a negative value when the
// argument cannot be decoded.
static inline EBPF_INLINE long
bpf_usdt_arg(struct pt_regs *ctx, USDTSpec *spec, u32 argument_index, u64 *result)
{
  if (argument_index >= USDT_MAX_ARGUMENTS || argument_index >= spec->argument_count) {
    DEBUG_PRINT("usdt: argument %u missing (count=%u)", argument_index, spec->argument_count);
    return -1;
  }

  USDTArgumentSpec *argument = &spec->arguments[argument_index];

  // Existing consumers register only unsigned, non-floating 64-bit values.
  // Supporting other forms requires width-specific user-memory reads and
  // post-read sign or zero extension below.
  if (argument->bit_shift != 0 || argument->is_signed || argument->is_float) {
    return -1;
  }

  u64 value = 0;
  long err  = 0;
  switch (argument->kind) {
  case USDT_ARGUMENT_CONSTANT: value = argument->value_offset; break;
  case USDT_ARGUMENT_REGISTER: err = usdt_read_register(ctx, argument->reg, &value); break;
  case USDT_ARGUMENT_REGISTER_DEREFERENCE:
    err = usdt_read_register(ctx, argument->reg, &value);
    if (!err) {
      u64 address = (u64)((s64)value + (s64)argument->value_offset);
      err         = bpf_probe_read_user(&value, sizeof(value), (void *)address);
    }
    break;
  default: return -1;
  }
  if (err) {
    DEBUG_PRINT("usdt: argument %u read failed: %ld", argument_index, err);
    return err;
  }

  *result = value;
  return 0;
}
