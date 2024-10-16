SHELL ?= bash
BPF_CLANG ?= clang-16
BPF_LINK ?= llvm-link-16
LLC ?= llc-16

DEBUG_FLAGS = -DOPTI_DEBUG -g

# Check if EXTERNAL flag is set
ifdef EXTERNAL
    EXTERNAL_FLAG = -DEXTERNAL_TRIGGER
else
    EXTERNAL_FLAG =
endif

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Valid values: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

# Valid values: release, debug
BUILD_TYPE ?= release

ifdef EXTERNAL
	TRACER_NAME ?= tracer.ebpf.$(BUILD_TYPE).$(EXTERNAL).$(TARGET_ARCH)
else
	TRACER_NAME ?= tracer.ebpf.$(BUILD_TYPE).$(TARGET_ARCH)
endif

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -target aarch64-linux-gnu
else
TARGET_FLAGS = -target x86_64-linux-gnu
endif

ifeq ($(BUILD_TYPE),debug)
	TARGET_FLAGS+=$(DEBUG_FLAGS)
endif

FLAGS=$(TARGET_FLAGS) \
	-fno-jump-tables \
	-nostdlib \
	-nostdinc \
	-ffreestanding \
	-O2 -emit-llvm -c $< \
	-Wall -Wextra -Werror \
	-Wno-address-of-packed-member \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-fno-stack-protector \
	$(EXTERNAL_FLAG)

SRCS := $(wildcard *.ebpf.c)
ifdef EXTERNAL
	OBJS := $(SRCS:.c=.$(BUILD_TYPE).$(EXTERNAL).$(TARGET_ARCH).o)
else
	OBJS := $(SRCS:.c=.$(BUILD_TYPE).$(TARGET_ARCH).o)
endif

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

debug:
	$(MAKE) BUILD_TYPE=debug

amd64:
	$(MAKE) TARGET_ARCH=amd64

arm64:
	$(MAKE) TARGET_ARCH=arm64

debug-amd64:
	$(MAKE) BUILD_TYPE=debug TARGET_ARCH=amd64

debug-arm64:
	$(MAKE) BUILD_TYPE=debug TARGET_ARCH=arm64

errors.h: ../../tools/errors-codegen/errors.json
	go run ../../tools/errors-codegen/main.go bpf $@

%.ebpf.c: errors.h ;

ifdef EXTERNAL
%.ebpf.$(BUILD_TYPE).$(EXTERNAL).$(TARGET_ARCH).o: %.ebpf.c
	$(BPF_CLANG) $(FLAGS) -o $@
else
%.ebpf.$(BUILD_TYPE).$(TARGET_ARCH).o: %.ebpf.c
	$(BPF_CLANG) $(FLAGS) -o $@
endif

$(TRACER_NAME): $(OBJS)
	$(BPF_LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

clean:
	rm -f *.o
