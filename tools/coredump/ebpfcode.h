// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#define TESTING_COREDUMP
#include "../../support/ebpf/types.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

struct cgo_ctx {
  u64 id, tp_base;
  int ret, debug;
};

__thread struct cgo_ctx *__cgo_ctx;

void bpf_log(const char *fmt, ...)
{
  void __bpf_log(const char *, int);
  if (__cgo_ctx->debug) {
    char msg[1024];
    size_t sz;
    va_list va;

    va_start(va, fmt);
    sz = vsnprintf(msg, sizeof msg, fmt, va);
    __bpf_log(msg, sz);
    va_end(va);
  }
}

#include "../../support/ebpf/beam_tracer.ebpf.c"
#include "../../support/ebpf/dotnet_tracer.ebpf.c"
#include "../../support/ebpf/go_labels.ebpf.c"
#include "../../support/ebpf/hotspot_tracer.ebpf.c"
#include "../../support/ebpf/interpreter_dispatcher.ebpf.c"
#include "../../support/ebpf/luajit_tracer.ebpf.c"
#include "../../support/ebpf/native_stack_trace.ebpf.c"
#include "../../support/ebpf/perl_tracer.ebpf.c"
#include "../../support/ebpf/php_tracer.ebpf.c"
#include "../../support/ebpf/python_tracer.ebpf.c"
#include "../../support/ebpf/ruby_tracer.ebpf.c"
#include "../../support/ebpf/system_config.ebpf.c"
#include "../../support/ebpf/v8_tracer.ebpf.c"

void initialize_rodata_variables(u64 new_inv_pac_mask, int new_ruby_skip_native_resume)
{
  // Initialize variables set via RODATA.
  inverse_pac_mask        = new_inv_pac_mask;
  ruby_skip_native_resume = new_ruby_skip_native_resume;

  // collect_trace rejects origin == 0. Use UINT16_MAX as a placeholder since
  // the coredump test harness has no real origin registry.
  origin_id_sampling = UINT16_MAX;
}

int unwind_traces(u64 id, int debug, u64 tp_base, void *ctx)
{
  struct cgo_ctx cgoctx = {
    .id      = id,
    .debug   = debug,
    .tp_base = tp_base,
    .ret     = -2, // default to an error, trace data sending resets this
  };
  __cgo_ctx = &cgoctx;
  int ret   = native_tracer_entry(ctx);
  __cgo_ctx = 0;
  return ret ? ret : cgoctx.ret;
}

int __bpf_copy_frame(u64, void *);

int bpf_perf_event_output(
  UNUSED void *ctx, UNUSED void *map, UNUSED unsigned long long flags, void *data, UNUSED int size)
{
  return __cgo_ctx->ret = __bpf_copy_frame(__cgo_ctx->id, data);
}

long bpf_ringbuf_output(UNUSED void *ringbuf, void *data, UNUSED u64 size, UNUSED u64 flags)
{
  return __cgo_ctx->ret = __bpf_copy_frame(__cgo_ctx->id, data);
}

int bpf_tail_call(void *ctx, UNUSED void *map, int index)
{
  switch (index) {
  case PROG_UNWIND_STOP: return unwind_stop(ctx);
  case PROG_UNWIND_NATIVE: return unwind_native(ctx);
  case PROG_UNWIND_PERL: return unwind_perl(ctx);
  case PROG_UNWIND_PHP: return unwind_php(ctx);
  case PROG_UNWIND_PYTHON: return unwind_python(ctx);
  case PROG_UNWIND_HOTSPOT: return unwind_hotspot(ctx);
  case PROG_UNWIND_RUBY: return unwind_ruby(ctx);
  case PROG_UNWIND_V8: return unwind_v8(ctx);
  case PROG_UNWIND_DOTNET: return unwind_dotnet(ctx);
  case PROG_UNWIND_DOTNET10: return unwind_dotnet10(ctx);
  case PROG_UNWIND_BEAM: return unwind_beam(ctx);
  case PROG_UNWIND_LUAJIT: return unwind_luajit(ctx);
  case PROG_GO_LABELS: return go_labels(ctx);
  default: return -1;
  }
}
