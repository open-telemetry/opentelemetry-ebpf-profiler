# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Fixtures for the tls integration tests: one per TLS access model, dialect and
# libc. Built for the host architecture only: the models are the same on both,
# and the machine-specific part is pfelf.File.StaticTLSOffset, unit-tested on
# its own.

.PHONY: all clean

ARCH := $(shell uname -m)

# The dialect names differ per architecture, the emitted relocations do not.
ifeq ($(ARCH),aarch64)
DESC_DIALECT ?= desc
GNU_DIALECT  ?= trad
else ifeq ($(ARCH),x86_64)
DESC_DIALECT ?= gnu2
GNU_DIALECT  ?= gnu
else
$(error Unsupported architecture $(ARCH))
endif

GCC      ?= $(ARCH)-linux-gnu-gcc
MUSL_GCC ?= $(ARCH)-linux-musl-gcc

CC_glibc := $(GCC)
CC_musl  := $(MUSL_GCC)

# One set of flags per access model and dialect. Hidden visibility is what lets
# the compiler emit the local-dynamic model at all.
FLAGS_desc    := -mtls-dialect=$(DESC_DIALECT)
FLAGS_gnu     := -mtls-dialect=$(GNU_DIALECT)
FLAGS_ie      := -ftls-model=initial-exec
# The hidden variants carry two thread-locals: their relocations reference no
# symbol, so only the addend tells which variable each one is for.
FLAGS_ie_hidden := -DHIDDEN_TLS -DEXTRA_HIDDEN_TLS_VAR -ftls-model=initial-exec
FLAGS_ld        := -DHIDDEN_TLS -DEXTRA_HIDDEN_TLS_VAR -ftls-model=local-dynamic \
                   -mtls-dialect=$(GNU_DIALECT)
FLAGS_ld_desc   := -DHIDDEN_TLS -DEXTRA_HIDDEN_TLS_VAR -ftls-model=local-dynamic \
                   -mtls-dialect=$(DESC_DIALECT)
# 128KiB of TLS ahead of the variable, which puts its static TP offset above
# tls.minUserAddr, the only shape where the descriptor's resolver has to be
# matched for it to resolve.
FLAGS_desc_big  := -DBIG_TLS -mtls-dialect=$(DESC_DIALECT)
# Defined but never referenced: no relocation, and so no access model. Library
# only, an executable would resolve it against its own PT_TLS.
FLAGS_noreloc   := -DNO_REFERENCE

LIBCS        := glibc musl
# Variants an executable can link and run. noreloc is built as a library only.
VARIANTS     := desc gnu ie ie_hidden ld ld_desc desc_big
LIB_VARIANTS := $(VARIANTS) noreloc

LIB_SRC := tlsvar_lib.c tlsvar_lib.h
EXE_SRC := tlsvar.c tlsvar_lib.h

BINARIES := \
	$(foreach libc,$(LIBCS),tlsvar_exe_$(libc) tlsvar_dlopen_$(libc) \
		$(foreach v,$(VARIANTS),libtlsvar_$(libc)_$(v).so tlsvar_lib_$(libc)_$(v))) \
	tlsvar_dlopen_glibc_nopie \
	libtlsvar_glibc_noreloc.so

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

# $(1): libc, $(2): variant. The executable links the library at startup, so
# its TLS block is part of the initial set.
define lib_rule
libtlsvar_$(1)_$(2).so: $$(LIB_SRC)
	$$(CC_$(1)) -shared -fPIC $$(FLAGS_$(2)) -o $$@ $$<
endef
define exe_rule
tlsvar_lib_$(1)_$(2): $$(EXE_SRC) libtlsvar_$(1)_$(2).so
	$$(CC_$(1)) -o $$@ $$< -L. -ltlsvar_$(1)_$(2) -Wl,-rpath='$$$$ORIGIN'
endef
$(foreach libc,$(LIBCS),\
	$(foreach v,$(LIB_VARIANTS),$(eval $(call lib_rule,$(libc),$(v))))\
	$(foreach v,$(VARIANTS),$(eval $(call exe_rule,$(libc),$(v)))))

# local-exec: the variable sits in the executable's own static TLS block, with
# no relocation to resolve.
tlsvar_exe_glibc: $(EXE_SRC) $(LIB_SRC)
	$(GCC) -o $@ $< tlsvar_lib.c

tlsvar_exe_musl: $(EXE_SRC) $(LIB_SRC)
	$(MUSL_GCC) -static -o $@ $< tlsvar_lib.c

# dlopen drivers: the module is loaded after startup, which is what forces
# dynamic TLS. The library to load is passed on the command line.
tlsvar_dlopen_glibc: $(EXE_SRC)
	$(GCC) -DUSE_DLOPEN -o $@ $<

tlsvar_dlopen_musl: $(EXE_SRC)
	$(MUSL_GCC) -DUSE_DLOPEN -o $@ $<

# Non-PIE: glibc allocates the dynamic descriptor's tls_index on the brk heap,
# which for a non-PIE process sits below 4 GiB, in the same range as a
# plausible static TP-relative offset. On aarch64 only dereferencing it
# separates the two. No musl counterpart: mallocng serves this from mmap, well
# above 4 GiB.
tlsvar_dlopen_glibc_nopie: $(EXE_SRC)
	$(GCC) -DUSE_DLOPEN -no-pie -o $@ $<
