#ifndef OPTI_TSD_H
#define OPTI_TSD_H

#include "bpfdefs.h"

// tpbase_offset is declared in native_stack_trace.ebpf.c
extern u64 tpbase_offset;

// tsd_read reads from the Thread Specific Data location associated with the provided key.
static inline EBPF_INLINE int
tsd_read(const TSDInfo *tsi, const void *tsd_base, int key, void **out)
{
  const void *tsd_addr = tsd_base + tsi->offset;
  if (tsi->indirect) {
    // Read the memory pointer that contains the per-TSD key data
    if (bpf_probe_read_user(&tsd_addr, sizeof(tsd_addr), tsd_addr)) {
      goto err;
    }
  }

  tsd_addr += key * tsi->multiplier;

  DEBUG_PRINT("readTSD key %d from address 0x%lx", key, (unsigned long)tsd_addr);
  if (bpf_probe_read_user(out, sizeof(*out), tsd_addr)) {
    goto err;
  }
  return 0;

err:
  DEBUG_PRINT("Failed to read TSD from 0x%lx", (unsigned long)tsd_addr);
  increment_metric(metricID_UnwindErrBadTSDAddr);
  return -1;
}

// tls_read reads a TLS variable, either directly from static TLS or by
// traversing the Dynamic Thread Vector (DTV).
//
// For static TLS (module_id == 0) the variable is read directly at
// tsd_base + tls_offset.
//
// For dynamic TLS (module_id != 0) the DTV is an array of pointers to per-module
// TLS blocks, indexed by TLS module ID. On x86_64 the default TLS dialect uses
// General Dynamic (GD) relocations (R_X86_64_DTPMOD64) rather than TLSDESC, so
// the DTV path is the primary mechanism for resolving thread-local variables in
// shared libraries. This path is also needed on other platforms when TLSDESC is
// unavailable.
//
// Parameters:
//   dtvi:       DTVInfo extracted from __tls_get_addr disassembly (offset, multiplier)
//   tsd_base:   thread pointer base (from tsd_get_base)
//   module_id:  TLS module ID for the target DSO (from DTPMOD64 relocation), or 0 for static TLS
//   tls_offset: TP-relative offset (static), or offset within the module's TLS block (dynamic)
//   out:        pointer to store the result
static inline EBPF_INLINE int
tls_read(const DTVInfo *dtvi, const void *tsd_base, u32 module_id, u64 tls_offset, void **out)
{
  // For static TLS the block is the static TLS area at the thread pointer; for
  // dynamic TLS it is the module's block, located via the DTV.
  const void *tls_block = tsd_base;
  if (module_id != 0) {
    // DTV access is always indirect: TP+offset yields a pointer to the DTV array,
    // which must be dereferenced before indexing by module ID.
    const void *dtv_ptr;
    if (bpf_probe_read_user(&dtv_ptr, sizeof(dtv_ptr), tsd_base + dtvi->offset)) {
      goto err;
    }

    // Index into the DTV to find this module's TLS block base address.
    // DTV layout: [generation, module1_block, module2_block, ...]
    // Entry size varies: 8 bytes (musl) or 16 bytes (glibc).
    u64 dtv_entry_offset = (u64)module_id * dtvi->multiplier;
    if (bpf_probe_read_user(&tls_block, sizeof(tls_block), (void *)(dtv_ptr + dtv_entry_offset))) {
      goto err;
    }
  }

  // Read the actual TLS variable at tls_block + tls_offset.
  if (bpf_probe_read_user(out, sizeof(*out), tls_block + tls_offset)) {
    goto err;
  }

  DEBUG_PRINT("readTLS module %d, tls_offset 0x%llx", module_id, (unsigned long long)tls_offset);
  return 0;

err:
  DEBUG_PRINT("Failed to read TLS for module %d", module_id);
  increment_metric(metricID_UnwindErrBadDTVRead);
  return -1;
}

// tsd_get_base looks up the base address for TSD variables (TPBASE).
static inline EBPF_INLINE int tsd_get_base(void **tsd_base)
{
#ifdef TESTING_COREDUMP
  *tsd_base = (void *)__cgo_ctx->tp_base;
  return 0;
#else
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // We need to read task->thread.fsbase (on x86_64), but we can't do so because
  // we might have been compiled with different kernel headers, so the struct layout
  // is likely to be different.
  // tpbase_offset is populated with the offset of `fsbase` or equivalent field
  // relative to a `task_struct`, so we use that instead.
  void *tpbase_ptr = ((char *)task) + tpbase_offset;
  if (bpf_probe_read_kernel(tsd_base, sizeof(void *), tpbase_ptr)) {
    DEBUG_PRINT("Failed to read tpbase value");
    increment_metric(metricID_UnwindErrBadTPBaseAddr);
    return -1;
  }

  return 0;
#endif
}

#endif // OPTI_TSD_H
