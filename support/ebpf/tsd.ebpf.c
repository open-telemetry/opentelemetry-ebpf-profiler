// This file contains the code and map definitions for Thread Local Storage (TLS) access

#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"
#include "types.h"

// codedump_addr is used to communicate the address of kernel function to eBPF code.
// It is used by extract_tpbase_offset.
bpf_map_def SEC("maps") codedump_addr = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = 1,
};

// codedump_code is populated by `codedump` it is meant to contain the first
// CODEDUMP_BYTES bytes of the function code requested via codedump_addr.
bpf_map_def SEC("maps") codedump_code = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = CODEDUMP_BYTES,
  .max_entries = 1,
};

// codedump extracts the first CODEDUMP_BYTES bytes of code from the function at
// address codedump_addr[0], and stores them in codedump_code[0].
SEC("tracepoint/syscalls/sys_enter_bpf")
int tracepoint__sys_enter_bpf(struct pt_regs *ctx) {
  u32 key0 = 0;
  int ret;
  u8 code[CODEDUMP_BYTES];

  // Read address of aout_dump_debugregs, provided by userspace
  void **paddr = bpf_map_lookup_elem(&codedump_addr, &key0);
  if (!paddr) {
    DEBUG_PRINT("Failed to look up codedump_addr for function address");
    return -1;
  }

  // Read first few bytes of aout_dump_debugregs code
  ret = bpf_probe_read(code, sizeof(code), *paddr);
  if (ret) {
    DEBUG_PRINT("Failed to read code from 0x%lx: error code %d", (unsigned long) *paddr, ret);
    return -1;
  }

  // Copy the bytes to a map, for userspace processing
  ret = bpf_map_update_elem(&codedump_code, &key0, code, BPF_ANY);
  if (ret) {
    DEBUG_PRINT("Failed to store code: error code %d", ret);
    return -1;
  }

  return 0;
}
