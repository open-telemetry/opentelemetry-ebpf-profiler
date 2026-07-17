# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Makefile to build test binaries for processcontext and threadcontext integration tests.
#
# These binaries exercise the different TLS dialects and access models across
# libc and architecture combinations:
#   - default dialect (gnu2 on x86-64, desc on aarch64): general-dynamic via TLS descriptors
#   - alternate dialect (gnu on x86-64, trad on aarch64): general-dynamic via __tls_get_addr
#   - initial-exec model (_ie)
#   - local-dynamic model (_ld), which requires the TLS symbol to be hidden

.PHONY: all clean

ARCH=$(shell uname -m)

ifeq ($(ARCH),aarch64)
TLS_DIALECT?=desc
TLS_DIALECT_ALT?=trad
else
TLS_DIALECT?=gnu2
TLS_DIALECT_ALT?=gnu
endif


# Compilers (override on command line if needed)
GCC       ?= $(ARCH)-linux-gnu-gcc
MUSL_GCC  ?= $(ARCH)-linux-musl-gcc


BINARIES := \
	processctx_exe_glibc processctx_exe_musl \
	processctx_lib_glibc processctx_lib_musl \
	processctx_lib_glibc_gnu processctx_lib_musl_gnu \
	processctx_lib_glibc_ie processctx_lib_musl_ie \
	processctx_lib_glibc_ld processctx_lib_musl_ld \
	processctx_dlopen_glibc processctx_dlopen_musl

all: $(BINARIES)

clean:
	rm -f $(BINARIES) *.so

processctx_exe_glibc: processctx.c processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< processctx_lib.c otel_process_ctx.c

processctx_exe_musl: processctx.c processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -mtls-dialect=$(TLS_DIALECT) -o $@ $< processctx_lib.c otel_process_ctx.c -static

# Shared library flavours.
# Default dialect (general-dynamic, TLS descriptors).
libprocessctx_glibc.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

libprocessctx_musl.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT) -o $@ $< otel_process_ctx.c

# Alternate dialect (general-dynamic via __tls_get_addr).
libprocessctx_glibc_gnu.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT_ALT) -o $@ $< otel_process_ctx.c

libprocessctx_musl_gnu.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -mtls-dialect=$(TLS_DIALECT_ALT) -o $@ $< otel_process_ctx.c

# Initial-exec model.
libprocessctx_glibc_ie.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -ftls-model=initial-exec -o $@ $< otel_process_ctx.c

libprocessctx_musl_ie.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -ftls-model=initial-exec -o $@ $< otel_process_ctx.c

# Local-dynamic model (requires a hidden TLS symbol).
libprocessctx_glibc_ld.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(GCC) -shared -fPIC -DHIDDEN_TLS -ftls-model=local-dynamic -mtls-dialect=$(TLS_DIALECT_ALT) -o $@ $< otel_process_ctx.c

libprocessctx_musl_ld.so: processctx_lib.c processctx_lib.h otel_process_ctx.c otel_process_ctx.h
	$(MUSL_GCC) -shared -fPIC -DHIDDEN_TLS -ftls-model=local-dynamic -mtls-dialect=$(TLS_DIALECT_ALT) -o $@ $< otel_process_ctx.c

# Executables linking the shared libraries at startup.
processctx_lib_glibc: processctx.c processctx_lib.h libprocessctx_glibc.so
	$(GCC) -o $@ $< -L. -lprocessctx_glibc -Wl,-rpath='$$ORIGIN'

processctx_lib_musl: processctx.c processctx_lib.h libprocessctx_musl.so
	$(MUSL_GCC) -o $@ $< -L. -lprocessctx_musl -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

processctx_lib_glibc_gnu: processctx.c processctx_lib.h libprocessctx_glibc_gnu.so
	$(GCC) -o $@ $< -L. -lprocessctx_glibc_gnu -Wl,-rpath='$$ORIGIN'

processctx_lib_musl_gnu: processctx.c processctx_lib.h libprocessctx_musl_gnu.so
	$(MUSL_GCC) -o $@ $< -L. -lprocessctx_musl_gnu -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

processctx_lib_glibc_ie: processctx.c processctx_lib.h libprocessctx_glibc_ie.so
	$(GCC) -o $@ $< -L. -lprocessctx_glibc_ie -Wl,-rpath='$$ORIGIN'

processctx_lib_musl_ie: processctx.c processctx_lib.h libprocessctx_musl_ie.so
	$(MUSL_GCC) -o $@ $< -L. -lprocessctx_musl_ie -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

processctx_lib_glibc_ld: processctx.c processctx_lib.h libprocessctx_glibc_ld.so
	$(GCC) -o $@ $< -L. -lprocessctx_glibc_ld -Wl,-rpath='$$ORIGIN'

processctx_lib_musl_ld: processctx.c processctx_lib.h libprocessctx_musl_ld.so
	$(MUSL_GCC) -o $@ $< -L. -lprocessctx_musl_ld -Wl,-rpath=/lib/x86_64-linux-musl/ -Wl,-rpath='$$ORIGIN'

processctx_dlopen_glibc: processctx.c
	$(GCC) -o $@ $< -DUSE_DLOPEN

processctx_dlopen_musl: processctx.c
	$(MUSL_GCC) -o $@ $< -DUSE_DLOPEN -Wl,-rpath=/lib/x86_64-linux-musl/
