// This file contains helpers for reading Go runtime structures from eBPF programs.

#ifndef OPTI_GO_RUNTIME_H
#define OPTI_GO_RUNTIME_H

#include "bpfdefs.h"
#include "tsd.h"
#include "types.h"

// go_get_g_ptr reads the current G (goroutine) pointer from thread-local storage.
// TLS always contains the G that is currently executing on the thread. During
// systemstack/mcall, this is g0 (the system goroutine) since we are on the
// system stack.
//
// On aarch64, the resolution path depends on whether the binary actually uses
// cgo at runtime, which is not the same as buildinfo CGO_ENABLED:
//
//   - Pure-Go binaries (no `import "C"`): runtime.iscgo is false. The Go runtime
//     never initialises TPIDR_EL0 for its threads ([1]), and load_g keeps g in R28.
//   - Cgo binaries: libc initialises TPIDR_EL0 via pthread_create; load_g reads
//     g from *(TPIDR_EL0 + tls_g_offset).
//
// The userspace TLS-offset extractor gates on buildinfo CGO_ENABLED only [2],
// so it returns a non-zero offset for any binary built with CGO_ENABLED=1,
// including pure-Go binaries where runtime.iscgo is false. 
// To handle this safely we try TLS first and fall back to r28 if the read fails
// or returns 0. R28 is the ABI-reserved register for the current goroutine
// on aarch64 [3] and is always populated while executing pure Go code.
//
// [1] https://github.com/golang/go/blame/0259df17feb288f1e24517516939b67876c2627b/src/runtime/sys_linux_arm64.s#L705
// [2] https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/abd95fe39bdfcd00c8079d152123d38f459a6ff0/libpf/pfelf/file.go#L615
// [3] https://github.com/golang/go/blob/0259df17feb288f1e24517516939b67876c2627b/src/cmd/compile/abi-internal.md?plain=1#L549
static inline EBPF_INLINE u64 go_get_g_ptr(struct GoLabelsOffsets *offs, UnwindState *state)
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

  if (offs->tls_offset != 0 && tls_base != NULL) {
    if (bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((s64)tls_base + offs->tls_offset))) {
      DEBUG_PRINT("cl: failed to read g_addr via TLS, tls_base(%lx)", (unsigned long)tls_base);
      g_addr = 0;
    }
  }

#if defined(__aarch64__)
  // Fallback to r28 when TLS is either not configured (pure-Go binary or
  // mis-detected as cgo at build time) or when the TLS read failed. On
  // aarch64 r28 holds the current g while executing Go runtime code.
  if (g_addr == 0) {
    g_addr = state->r28;
    DEBUG_PRINT("cl: g_addr fallback via r28 = 0x%lx", (unsigned long)g_addr);
  }
#elif defined(__x86_64__)
  if (g_addr == 0) {
    DEBUG_PRINT("cl: TLS offset for g pointer missing for amd64");
    return 0;
  }
#endif

  DEBUG_PRINT("cl: g_addr 0x%lx", (unsigned long)g_addr);
  return g_addr;
}

// go_get_m_ptr reads the M (machine/OS thread) pointer for the current goroutine.
// It does so by reading the G (goroutine) pointer from thread-local storage,
// then following the g.m pointer.
static inline EBPF_INLINE void *go_get_m_ptr(struct GoLabelsOffsets *offs, UnwindState *state)
{
  u64 g_addr = go_get_g_ptr(offs, state);
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
