# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Test binaries for the processcontext and threadcontext integration tests.

.PHONY: all clean

ARCH=$(shell uname -m)

ifeq ($(ARCH),aarch64)
TLS_DIALECT?=desc
else
TLS_DIALECT?=gnu2
endif


# Compilers (override on command line if needed)
GCC       ?= $(ARCH)-linux-gnu-gcc
MUSL_GCC  ?= $(ARCH)-linux-musl-gcc


BINARIES := \
	processctx_exe_glibc \
	libprocessctx_glibc.so libprocessctx_musl.so \
	processctx_dlopen_glibc processctx_dlopen_musl

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

# -rdynamic puts the executable's own otel_thread_ctx_v1 in .dynsym, where the
# profiler looks for it: nothing references it from outside, so the linker would
# otherwise leave it in .symtab alone. A publisher has to export the variable
# for the same reason, which rules out a static binary, having no .dynsym.
processctx_exe_glibc: processctx.c processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -mtls-dialect=$(TLS_DIALECT) -rdynamic -o $@ $< processctx_lib.c otel_process_ctx.c

libprocessctx_glibc.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

libprocessctx_musl.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

processctx_dlopen_glibc: processctx.c
	$(GCC) -o $@ $< -DUSE_DLOPEN

processctx_dlopen_musl: processctx.c
	$(MUSL_GCC) -o $@ $< -DUSE_DLOPEN
