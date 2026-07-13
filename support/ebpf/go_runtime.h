// This file contains helpers for reading Go runtime structures from eBPF programs.

#ifndef OPTI_GO_RUNTIME_H
#define OPTI_GO_RUNTIME_H

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

typedef struct GoRuntimeCtx {
  u64 g;
  u64 m;
  u64 m_g0;
  u64 m_gsignal;
  u64 m_curg;
} GoRuntimeCtx;

static inline EBPF_INLINE u64 go_get_g_register(UNUSED UnwindState *state)
{
#if defined(__aarch64__)
  // On aarch64 for !iscgo programs the g is only stored in r28 register.
  // We want to retrieve g from r28 when available.
  // See https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/1455.
  return state->r28;
#else
  return 0;
#endif
}

// go_get_g_ptr reads the current goroutine pointer from thread-local storage
// when the TLS offset is known. On arm64 falls back to r28 when TLS is unavailable.
static inline EBPF_INLINE u64 go_get_g_ptr(struct GoRuntimeOffsets *offs, UnwindState *state)
{
  u64 g_register = go_get_g_register(state);

  if (offs->tls_offset == 0) {
    DEBUG_PRINT("go: TLS offset for g pointer missing; using register fallback if available");
    return g_register;
  }

  u64 g_addr     = 0;
  void *tls_base = NULL;
  if (tsd_get_base(&tls_base) < 0) {
    DEBUG_PRINT("go: failed to get tsd base; using register fallback if available");
    return g_register;
  }
  DEBUG_PRINT(
    "go: read tsd_base at 0x%lx, g offset: %d", (unsigned long)tls_base, offs->tls_offset);

  if (bpf_probe_read_user(&g_addr, sizeof(void *), (void *)((s64)tls_base + offs->tls_offset))) {
    DEBUG_PRINT(
      "go: failed to read g_addr, tls_base(%lx); using register fallback if available",
      (unsigned long)tls_base);
  }

  return g_addr ? g_addr : g_register;
}

// go_get_m_ptr reads the machine/OS thread pointer for the current goroutine.
// It does so by reading the goroutine pointer then following the g.m pointer.
static inline EBPF_INLINE void *go_get_m_ptr(struct GoRuntimeOffsets *offs, UnwindState *state)
{
  u64 g_addr = go_get_g_ptr(offs, state);
  if (!g_addr) {
    return NULL;
  }

  DEBUG_PRINT("go: reading m_ptr_addr at 0x%lx + 0x%x", (unsigned long)g_addr, offs->m_offset);
  void *m_ptr_addr;
  if (bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m_offset))) {
    DEBUG_PRINT("go: failed m_ptr_addr");
    return NULL;
  }
  DEBUG_PRINT("go: m_ptr_addr 0x%lx", (unsigned long)m_ptr_addr);
  return m_ptr_addr;
}

static inline EBPF_INLINE ErrorCode go_validate_runtime_offsets(GoRuntimeOffsets *offs)
{
  if (offs->m_offset == 0) {
    DEBUG_PRINT("go runtime: missing offsets");
    return ERR_GO_NO_OFFSETS;
  }
  return ERR_OK;
}

// go_runtime_load_ctx reads g, g.m, and the runtime.m prefix into ctx.
static inline EBPF_INLINE ErrorCode go_runtime_load_ctx(
  struct GoRuntimeOffsets *offs, UnwindState *state, u8 *scratch, GoRuntimeCtx *ctx)
{
  ctx->g = go_get_g_ptr(offs, state);
  if (!ctx->g) {
    return ERR_GO_RUNTIME_LOAD_FAILURE;
  }

  u64 m_ptr = 0;
  if (bpf_probe_read_user(&m_ptr, sizeof(m_ptr), (void *)(ctx->g + offs->m_offset))) {
    DEBUG_PRINT("go runtime: failed to read g.m");
    return ERR_GO_RUNTIME_LOAD_FAILURE;
  }
  if (!m_ptr) {
    DEBUG_PRINT("go runtime: g.m is nil");
    return ERR_GO_RUNTIME_LOAD_FAILURE;
  }

  const u64 max_off = sizeof(((GoUnwindScratchSpace *)0)->buf) - sizeof(u64);
  u64 curg          = offs->curg;
  u64 gsignal       = offs->m_gsignal;
  if (curg > max_off || gsignal > max_off) {
    DEBUG_PRINT("go runtime: m offsets exceed scratch");
    return ERR_GO_RUNTIME_LOAD_FAILURE;
  }
  u64 prefix_size = curg + sizeof(u64);

  if (bpf_probe_read_user(scratch, prefix_size, (void *)m_ptr)) {
    DEBUG_PRINT("go runtime: failed to read m prefix");
    return ERR_GO_RUNTIME_LOAD_FAILURE;
  }

  ctx->m         = m_ptr;
  ctx->m_g0      = *(u64 *)(scratch + 0);
  ctx->m_gsignal = *(u64 *)(scratch + gsignal);
  ctx->m_curg    = *(u64 *)(scratch + curg);
  return ERR_OK;
}

#if defined(__aarch64__)

// go_asmcgocall_is_nosave mirrors the nosave tests in runtime.asmcgocall
// https://github.com/golang/go/blob/339c903a75c3fe936fb4ed6c355d15e6081d6af3/src/runtime/asm_arm64.s#L960
//
// The FP chain is valid on the nosave path.
// Returns true if the caller should goto fp_unwind_fallback.
static inline EBPF_INLINE bool go_asmcgocall_is_nosave(const GoRuntimeCtx *ctx)
{
  // CBZ g, nosave
  // https://github.com/golang/go/blob/cc85462b3d23193e4861813ea85e254cfe372403/src/runtime/asm_arm64.s#L939
  if (!ctx->g) {
    DEBUG_PRINT("asmcgocall: fp fallback (nosave g==nil)");
    return true;
  }

  // MOVD	m_gsignal(R8), R3
  // CMP R3, g
  // https://github.com/golang/go/blob/339c903a75c3fe936fb4ed6c355d15e6081d6af3/src/runtime/asm_arm64.s#L974
  if (ctx->g == ctx->m_gsignal) {
    DEBUG_PRINT("asmcgocall: fp fallback (nosave g==m.gsignal)");
    return true;
  }

  // MOVD	m_g0(R8), R3
  // CMP	R3, g
  // https://github.com/golang/go/blob/339c903a75c3fe936fb4ed6c355d15e6081d6af3/src/runtime/asm_arm64.s#L977
  if (ctx->g == ctx->m_g0) {
    // Post-gosave also has g==m.g0 when gosave_systemstack_switch switched tls to m.g0.
    // curg!=g distinguishes it from asm nosave.
    if (ctx->m_curg != 0 && ctx->m_curg != ctx->g) {
      DEBUG_PRINT("asmcgocall: post-gosave (g==m.g0, curg is user g)");
      return false;
    }
    DEBUG_PRINT("asmcgocall: fp fallback (nosave g==m.g0)");
    return true;
  }
  return false;
}

// go_unwind_asmcgocall recovers the caller frame when the unwinder is
// inside runtime.asmcgocall on aarch64.
static inline EBPF_INLINE ErrorCode go_unwind_asmcgocall(PerCPURecord *record, UnwindState *state)
{
  increment_metric(metricID_UnwindGoAsmcgocallAttempts);

  GoRuntimeOffsets *offs = &record->goOffsets;
  ErrorCode err          = go_validate_runtime_offsets(offs);
  if (err != ERR_OK) {
    increment_metric(metricID_UnwindGoAsmcgocallUnwindFailure);
    return err;
  }

  u8 *scratch      = record->goUnwindScratch.buf;
  GoRuntimeCtx ctx = {};

  err = go_runtime_load_ctx(offs, state, scratch, &ctx);
  // ctx.g == 0 is a valid nosave path handled in go_asmcgocall_is_nosave.
  if (err != ERR_OK && ctx.g) {
    goto unwind_failure;
  }

  if (go_asmcgocall_is_nosave(&ctx)) {
    goto unwind_fp;
  }

  if (!ctx.m_curg) {
    DEBUG_PRINT("asmcgocall: m.curg is nil");
    goto unwind_failure;
  }

  // asmcgocall does not call dropg, so m.curg keeps pointing at the user g for
  // the whole call. Only tls is switched to m.g0 after gosave_systemstack_switch.
  //
  // We are in the pre-gosave path so the fp chain is valid.
  // Safety guard to check that the running goroutine is the same as curg to avoid reading stale
  // data.
  if (ctx.g == ctx.m_curg) {
    DEBUG_PRINT("asmcgocall: fp fallback (pre-gosave g==curg)");
    goto unwind_fp;
  }

  // Post-gosave because g == m.g0 happens after gosave_systemstack_switch switched tls to m.g0.
  // One read to cover:
  //   sizeof(g.m) + sched_bp_off + sizeof(bp).
  const u64 max_bp_off = sizeof(record->goUnwindScratch.buf) - 2 * sizeof(u64);
  u64 bp_off           = offs->sched_bp_off;
  if (bp_off > max_bp_off) {
    DEBUG_PRINT("asmcgocall: sched_bp_off exceeds scratch");
    goto unwind_failure;
  }
  u64 gobuf_read_size = sizeof(u64) + bp_off + sizeof(u64);
  if (bpf_probe_read_user(scratch, gobuf_read_size, (void *)(ctx.m_curg + offs->m_offset))) {
    DEBUG_PRINT("asmcgocall: failed to read curg gobuf");
    goto unwind_failure;
  }

  u64 curg_m = *((u64 *)scratch);
  // Safety guard to ensure m.curg still point at a g bound to this m before we trust gobuf.
  if (curg_m != ctx.m) {
    DEBUG_PRINT("asmcgocall: stale curg (curg.m != m)");
    goto unwind_failure;
  }

  // We need to read g.sched that is 8 bytes after g.m.
  u8 *gobuf    = scratch + sizeof(u64);
  u64 saved_sp = *((u64 *)gobuf);
  u64 saved_bp = *((u64 *)(gobuf + bp_off));
  if (!saved_sp || !saved_bp) {
    DEBUG_PRINT("asmcgocall: gobuf sp/bp not populated");
    goto unwind_failure;
  }

  state->fp  = saved_bp;
  state->lr  = 0;
  state->r28 = ctx.m_curg;
  // asmcgocall PC is a marker. unwind one frame to the caller.
unwind_fp:
  if (!unwinder_unwind_frame_pointer(state)) {
    DEBUG_PRINT("asmcgocall: fp unwind failed");
    err = ERR_GO_ASMCGOCALL_UNWIND_FAILURE;
    goto unwind_failure;
  }
  increment_metric(metricID_UnwindGoAsmcgocallSuccess);
  return ERR_OK;
unwind_failure:
  increment_metric(metricID_UnwindGoAsmcgocallUnwindFailure);
  if (err == ERR_OK) {
    err = ERR_GO_ASMCGOCALL_UNWIND_FAILURE;
  }
  return err;
}
#endif // __aarch64__

#endif // OPTI_GO_RUNTIME_H
