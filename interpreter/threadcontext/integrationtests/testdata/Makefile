# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Makefile to build test binaries for threadcontext TLS offset extraction tests.
#
# These binaries exercise the different TLS models across libc and architecture
# combinations. The unit tests parse these ELF files (without executing them)
# to verify that the Loader correctly computes TLS offsets.
#
# Available cross-compilers are auto-detected. Targets that require unavailable
# compilers are skipped.

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


BINARIES := threadctx_exe_glibc threadctx_exe_musl threadctx_lib_glibc threadctx_lib_musl threadctx_dlopen_glibc threadctx_dlopen_musl

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

threadctx_exe_glibc: threadctx.c threadctx_lib.c threadctx_lib.h
	$(GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< threadctx_lib.c

threadctx_exe_musl: threadctx.c threadctx_lib.c threadctx_lib.h
	$(MUSL_GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< threadctx_lib.c -static

libthreadctx_glibc.so: threadctx_lib.c threadctx_lib.h
	$(GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $<

libthreadctx_musl.so: threadctx_lib.c threadctx_lib.h
	$(MUSL_GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $<

threadctx_lib_glibc: threadctx.c threadctx_lib.h libthreadctx_glibc.so
	$(GCC) -o $@ $< -L. -lthreadctx_glibc -Wl,-rpath='$$ORIGIN'

threadctx_lib_musl: threadctx.c threadctx_lib.h libthreadctx_musl.so
	$(MUSL_GCC) -o $@ $< -L. -lthreadctx_musl -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

threadctx_dlopen_glibc: threadctx.c
	$(GCC) -o $@ $< -DUSE_DLOPEN

threadctx_dlopen_musl: threadctx.c
	$(MUSL_GCC) -o $@ $< -DUSE_DLOPEN -Wl,-rpath=/lib/x86_64-linux-musl/ 
