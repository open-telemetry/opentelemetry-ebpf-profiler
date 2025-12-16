#ifndef OPTI_GOROUTINE_H
#define OPTI_GOROUTINE_H

#include "bpfdefs.h"
#include "tsd.h"
#include "types.h"

static EBPF_INLINE void *get_go_m_ptr(struct GoLabelsOffsets *offs, UNUSED UnwindState *state)
{
  u64 g_addr     = 0;
  void *tls_base = NULL;
  if (tsd_get_base(&tls_base) < 0) {
    DEBUG_PRINT("cl mptr new: failed to get tsd base; can't read m_ptr");
    return NULL;
  }
  DEBUG_PRINT(
    "cl mptr new: read tsd_base at 0x%lx, g offset: %d", (unsigned long)tls_base, offs->tls_offset);

  if (offs->tls_offset == 0 || tls_base == 0) {
#if defined(__aarch64__)
    // On aarch64 for !iscgo programs the g is only stored in r28 register.
    g_addr = state->r28;
#elif defined(__x86_64__)
    DEBUG_PRINT("cl mptr new: TLS offset for g pointer missing for amd64");
    return NULL;
#endif
  }

  if (g_addr == 0) {
    if (bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((s64)tls_base + offs->tls_offset))) {
      DEBUG_PRINT("cl mptr new: failed to read g_addr, tls_base(%lx)", (unsigned long)tls_base);
      return NULL;
    }
  }

  DEBUG_PRINT(
    "cl mptr new: reading m_ptr_addr at 0x%lx + 0x%x", (unsigned long)g_addr, offs->m_offset);
  void *m_ptr_addr;
  if (bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m_offset))) {
    DEBUG_PRINT("cl: failed m_ptr_addr");
    return NULL;
  }
  DEBUG_PRINT("cl mptr new: returning 0x%lx", (unsigned long)m_ptr_addr);
  return m_ptr_addr;
}

#endif
