# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Makefile to build test binaries for processcontext and threadcontext integration tests.
#
# These binaries exercise the different TLS models across libc and architecture combinations.

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


# Only the static executable variant is built; shared-lib and dlopen targets remain for future thread-context support.
BINARIES := processctx_exe_glibc # processctx_exe_musl processctx_lib_glibc processctx_lib_musl processctx_dlopen_glibc processctx_dlopen_musl

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

processctx_exe_glibc: processctx.c processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< processctx_lib.c otel_process_ctx.c 

processctx_exe_musl: processctx.c processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< processctx_lib.c otel_process_ctx.c -static

libprocessctx_glibc.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

libprocessctx_musl.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

processctx_lib_glibc: processctx.c processctx_lib.h libprocessctx_glibc.so
	$(GCC) -o $@ $< -L. -lprocessctx_glibc -Wl,-rpath='$$ORIGIN'

processctx_lib_musl: processctx.c processctx_lib.h libprocessctx_musl.so
	$(MUSL_GCC) -o $@ $< -L. -lprocessctx_musl -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

processctx_dlopen_glibc: processctx.c
	$(GCC) -o $@ $< -DUSE_DLOPEN

processctx_dlopen_musl: processctx.c
	$(MUSL_GCC) -o $@ $< -DUSE_DLOPEN -Wl,-rpath=/lib/x86_64-linux-musl/ 
