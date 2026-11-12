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

static inline EBPF_INLINE long
usdt_read_register(struct pt_regs *ctx, u16 register_offset, u64 *value)
{
  return bpf_probe_read_kernel(value, sizeof(*value), (void *)ctx + register_offset);
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
  USDTSpecKey spec_key = {
    .pid             = pid,
    .virtual_address = usdt_probe_pc(ctx),
  };
  USDTSpec *spec = bpf_map_lookup_elem(&usdt_specs, &spec_key);
  if (!spec) {
    DEBUG_PRINT("usdt: spec missing pid=%u address=%lx", pid, spec_key.virtual_address);
    return NULL;
  }
  return spec;
}

// bpf_usdt_arg reads one argument from a specification returned by
// bpf_usdt_spec. It returns zero on success and a negative value when the
// argument cannot be decoded.
// Currently we only support unsigned 8-byte arguments, but we can extend this
// mechanism as the need arises.
static inline EBPF_INLINE long
bpf_usdt_arg(struct pt_regs *ctx, USDTSpec *spec, u32 argument_index, u64 *result)
{
  if (argument_index >= USDT_MAX_ARGUMENTS || argument_index >= spec->argument_count) {
    DEBUG_PRINT("usdt: argument %u missing (count=%u)", argument_index, spec->argument_count);
    return -1;
  }

  USDTArgumentSpec *argument = &spec->arguments[argument_index];

  u64 value = 0;
  long err  = 0;
  switch (argument->kind) {
  case USDT_ARGUMENT_CONSTANT: value = argument->value_offset; break;
  case USDT_ARGUMENT_REGISTER:
    err = usdt_read_register(ctx, argument->register_offset, &value);
    break;
  case USDT_ARGUMENT_REGISTER_DEREFERENCE:
    err = usdt_read_register(ctx, argument->register_offset, &value);
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
