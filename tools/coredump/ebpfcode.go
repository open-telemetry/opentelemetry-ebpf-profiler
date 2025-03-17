// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// This file contains the magic to include and build the ebpf C-code via CGO.
//
// The approach is to have a TLS variable (struct cgo_ctx *) that describe
// state of the eBPF program. This files defines that, and #includes all the
// eBPF code to be built in this unit. Additionally the main entry point
// "unwind_traces" that setups the TLS, and starts the unwinding is defined here.
// Also the tail call helper "bpf_tail_call" is overridden here, as it works in
// tandem with the main entry point's setjmp.

/*
#define TESTING
#define TESTING_COREDUMP
#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>
#include "../../support/ebpf/types.h"

struct cgo_ctx {
	jmp_buf jmpbuf;
	u64 id, tp_base;
	int ret;
	int debug;
};

__thread struct cgo_ctx *__cgo_ctx;

int bpf_log(const char *fmt, ...)
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

#include "../../support/ebpf/interpreter_dispatcher.ebpf.c"
#include "../../support/ebpf/native_stack_trace.ebpf.c"
#include "../../support/ebpf/dotnet_tracer.ebpf.c"
#include "../../support/ebpf/perl_tracer.ebpf.c"
#include "../../support/ebpf/php_tracer.ebpf.c"
#include "../../support/ebpf/python_tracer.ebpf.c"
#include "../../support/ebpf/hotspot_tracer.ebpf.c"
#include "../../support/ebpf/ruby_tracer.ebpf.c"
#include "../../support/ebpf/v8_tracer.ebpf.c"
#include "../../support/ebpf/system_config.ebpf.c"
#include "../../support/ebpf/go_labels.ebpf.c"

int unwind_traces(u64 id, int debug, u64 tp_base, void *ctx)
{
	struct cgo_ctx cgoctx;

	cgoctx.id = id;
	cgoctx.ret = 0;
	cgoctx.debug = debug;
	cgoctx.tp_base = tp_base;
	__cgo_ctx = &cgoctx;
	if (setjmp(cgoctx.jmpbuf) == 0) {
		cgoctx.ret = native_tracer_entry(ctx);
	}
	__cgo_ctx = 0;
	return cgoctx.ret;
}

// We don't want to call the actual `unwind_stop` function because it'd
// require us to properly emulate all the maps required for sending frames
// to usermode.
int coredump_unwind_stop(struct bpf_perf_event_data* ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  if (record->state.unwind_error) {
    push_error(&record->trace, record->state.unwind_error);
  }

  return 0;
}

int bpf_tail_call(void *ctx, bpf_map_def *map, int index)
{
	int rc = 0;
	switch (index) {
	case PROG_UNWIND_STOP:
		rc = coredump_unwind_stop(ctx);
		break;
	case PROG_UNWIND_NATIVE:
		rc = unwind_native(ctx);
		break;
	case PROG_UNWIND_PERL:
		rc = unwind_perl(ctx);
		break;
	case PROG_UNWIND_PHP:
		rc = unwind_php(ctx);
		break;
	case PROG_UNWIND_PYTHON:
		rc = unwind_python(ctx);
		break;
	case PROG_UNWIND_HOTSPOT:
		rc = unwind_hotspot(ctx);
		break;
	case PROG_UNWIND_RUBY:
		rc = unwind_ruby(ctx);
		break;
	case PROG_UNWIND_V8:
		rc = unwind_v8(ctx);
		break;
	case PROG_UNWIND_DOTNET:
		rc = unwind_dotnet(ctx);
		break;
  case PROG_GO_LABELS:
		rc = perf_go_labels(ctx);
		break;
	default:
		return -1;
	}
	__cgo_ctx->ret = rc;
	longjmp(__cgo_ctx->jmpbuf, 1);
}
*/
import "C"
