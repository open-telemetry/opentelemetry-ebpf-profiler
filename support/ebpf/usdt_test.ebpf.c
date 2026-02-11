// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// Test results map to communicate success/failure to userspace
struct usdt_test_results_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 64);
} usdt_test_results SEC(".maps");

// Helper to record test result
static EBPF_INLINE void record_result(UNUSED u32 probe_id, u64 value)
{
  bpf_map_update_elem(&usdt_test_results, &probe_id, &value, BPF_ANY);
}

// ============================================================================
// EBPF_INLINE helper functions containing probe logic
// These are called by both individual SEC probes and the multi-probe dispatcher
// ============================================================================

SEC("usdt/testprov/simple_probe")
int BPF_USDT(simple_probe, s32 x, s64 y, u64 z)
{
  u32 probe_id = 1;

  if (x == 42 && y == 1234567890 && z == 0xDEADBEEF) {
    record_result(probe_id, 1);
  } else {
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: memory_probe with args: s32 *x, s64 *y
SEC("usdt/testprov/memory_probe")
int BPF_USDT(memory_probe, u64 ptr0, u64 ptr1)
{
  u32 probe_id = 2;

  DEBUG_PRINT("memory_probe called: ptr0=0x%llx ptr1=0x%llx", ptr0, ptr1);

  s32 val0;
  s64 val1;
  if (
    bpf_probe_read_user(&val0, sizeof(val0), (void *)ptr0) ||
    bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("memory_probe: read failed");
    return -1;
  }

  DEBUG_PRINT("memory_probe: val0=%d val1=%lld", val0, val1);

  if (val0 == 42 && val1 == 1234567890) {
    DEBUG_PRINT("memory_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("memory_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: const_probe with arg: constant 100
SEC("usdt/testprov/const_probe")
int BPF_USDT(const_probe, s64 arg0)
{
  u32 probe_id = 3;

  DEBUG_PRINT("const_probe called: arg0=%lld", arg0);

  if (arg0 == 100) {
    DEBUG_PRINT("const_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("const_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: mixed_probe with args: s32 x, s64 *y, int c, double *f
SEC("usdt/testprov/mixed_probe")
int BPF_USDT(mixed_probe, s32 arg0, u64 ptr1, s32 arg2)
{
  u32 probe_id = 4;

  DEBUG_PRINT("mixed_probe called: arg0=%d ptr1=0x%llx arg2=%d", arg0, ptr1, arg2);

  s64 val1;
  if (bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("mixed_probe: read failed");
    return -1;
  }

  DEBUG_PRINT("mixed_probe: val1=%lld", val1);

  if (arg0 == 42 && val1 == 1234567890 && arg2 == 42) {
    DEBUG_PRINT("mixed_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("mixed_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: int32_args with args: s32 a=10, b=20, c=30
SEC("usdt/testprov/int32_args")
int BPF_USDT(int32_args, s32 arg0, s32 arg1, s32 arg2)
{
  u32 probe_id = 5;

  DEBUG_PRINT("int32_args called: arg0=%d arg1=%d arg2=%d", arg0, arg1, arg2);

  if (arg0 == 10 && arg1 == 20 && arg2 == 30) {
    DEBUG_PRINT("int32_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("int32_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: int64_args with args: s64 a=100, b=200
SEC("usdt/testprov/int64_args")
int BPF_USDT(int64_args, s64 arg0, s64 arg1)
{
  u32 probe_id = 6;

  DEBUG_PRINT("int64_args called: arg0=%lld arg1=%lld", arg0, arg1);

  if (arg0 == 100 && arg1 == 200) {
    DEBUG_PRINT("int64_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("int64_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: mixed_refs with args: s32 *a, s64 *b, s32 c
SEC("usdt/testprov/mixed_refs")
int BPF_USDT(mixed_refs, u64 ptr0, u64 ptr1, s32 arg2)
{
  u32 probe_id = 7;

  DEBUG_PRINT("mixed_refs called: ptr0=0x%llx ptr1=0x%llx arg2=%d", ptr0, ptr1, arg2);

  s32 val0;
  s64 val1;
  if (
    bpf_probe_read_user(&val0, sizeof(val0), (void *)ptr0) ||
    bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("mixed_refs: read failed");
    return -1;
  }

  DEBUG_PRINT("mixed_refs: val0=%d val1=%lld", val0, val1);

  if (val0 == 10 && val1 == 100 && arg2 == 30) {
    DEBUG_PRINT("mixed_refs: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("mixed_refs: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// Test probe logic: uint8_args with args: uint8_t a=5, b=10
SEC("usdt/testprov/uint8_args")
int BPF_USDT(uint8_args, u8 arg0, u8 arg1)
{
  u32 probe_id = 8;

  DEBUG_PRINT("uint8_args called: arg0=%u arg1=%u", arg0, arg1);

  if (arg0 == 5 && arg1 == 10) {
    DEBUG_PRINT("uint8_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("uint8_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

// ============================================================================
// Multi-probe dispatcher
// ============================================================================

// Multi-probe entrypoint that dispatches to individual handlers based on cookie
// Similar to cuda.ebpf.c, uses the low 32 bits of cookie for dispatch
SEC("usdt/usdt_test_multi")
int usdt_test_multi(struct pt_regs *ctx)
{
  // Extract user cookie from low 32 bits (high 32 bits contain spec ID)
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 probe_id    = (u32)(full_cookie & 0xFFFFFFFF);

  DEBUG_PRINT("usdt_test_multi called with probe_id=%u", probe_id);

  // Dispatch to inline helper functions (not SEC entry points)
  switch (probe_id) {
  case 1: return BPF_USDT_CALL(simple_probe, x, y, z);
  case 2: return BPF_USDT_CALL(memory_probe, ptr0, ptr1);
  case 3: return BPF_USDT_CALL(const_probe, arg0);
  case 4: return BPF_USDT_CALL(mixed_probe, arg0, ptr1, arg2);
  case 5: return BPF_USDT_CALL(int32_args, arg0, arg1, arg2);
  case 6: return BPF_USDT_CALL(int64_args, arg0, arg1);
  case 7: return BPF_USDT_CALL(mixed_refs, ptr0, ptr1, arg2);
  case 8: return BPF_USDT_CALL(uint8_args, arg0, arg1);
  default: DEBUG_PRINT("usdt_test_multi: unknown probe_id %u", probe_id); return 0;
  }
}
