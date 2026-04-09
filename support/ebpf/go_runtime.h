// This file contains helpers for reading Go runtime structures from eBPF programs.

#ifndef OPTI_GO_RUNTIME_H
#define OPTI_GO_RUNTIME_H

#include "bpfdefs.h"
#include "tsd.h"
#include "types.h"

// get_g_ptr reads the current G (goroutine) pointer from thread-local storage.
// TLS always contains the G that is currently executing on the thread. During
// systemstack/mcall, this is g0 (the system goroutine) since we are on the
// system stack.
//
// On aarch64, when tls_offset is 0 (non-CGO binaries), the G pointer is taken
// from the r28 register saved in the unwind state instead of TLS.
static EBPF_INLINE u64 get_g_ptr(struct GoLabelsOffsets *offs, UnwindState *state)
{
#if defined(__x86_64__)
  (void)state;
#endif
  u64 g_addr     = 0;
  void *tls_base = NULL;
  if (tsd_get_base(&tls_base) < 0) {
    DEBUG_PRINT("cl: failed to get tsd base; can't read g_addr");
    return 0;
  }
  DEBUG_PRINT(
    "cl: read tsd_base at 0x%lx, g offset: %d", (unsigned long)tls_base, offs->tls_offset);

  if (offs->tls_offset == 0) {
#if defined(__aarch64__)
    // On aarch64 for !iscgo programs the g is only stored in r28 register.
    g_addr = state->r28;
#elif defined(__x86_64__)
    DEBUG_PRINT("cl: TLS offset for g pointer missing for amd64");
    return 0;
#endif
  }

  if (g_addr == 0) {
    if (bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((s64)tls_base + offs->tls_offset))) {
      DEBUG_PRINT("cl: failed to read g_addr, tls_base(%lx)", (unsigned long)tls_base);
      return 0;
    }
  }

  DEBUG_PRINT("cl: g_addr 0x%lx", (unsigned long)g_addr);
  return g_addr;
}

// get_m_ptr reads the M (machine/OS thread) pointer for the current goroutine.
// It does so by reading the G (goroutine) pointer from thread-local storage,
// then following the g.m pointer.
__attribute__((unused)) static EBPF_INLINE void *
get_m_ptr(struct GoLabelsOffsets *offs, UnwindState *state)
{
  u64 g_addr = get_g_ptr(offs, state);
  if (!g_addr) {
    return NULL;
  }

  DEBUG_PRINT("cl: reading m_ptr_addr at 0x%lx + 0x%x", (unsigned long)g_addr, offs->m_offset);
  void *m_ptr_addr;
  if (bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m_offset))) {
    DEBUG_PRINT("cl: failed m_ptr_addr");
    return NULL;
  }
  DEBUG_PRINT("cl: m_ptr_addr 0x%lx", (unsigned long)m_ptr_addr);
  return m_ptr_addr;
}

#endif // OPTI_GO_RUNTIME_H
