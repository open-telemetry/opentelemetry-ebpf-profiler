SHELL ?= bash
BPF_CLANG ?= clang-17
BPF_LINK ?= llvm-link-17
STRIP ?= llvm-strip-17
LLC ?= llc-17
CLANG_FORMAT ?= clang-format-17

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Get the current build directory (absolute path).
BUILD_DIR := $(shell pwd)
# Use a placeholder like '.' or '/' as the new prefix.
REPRODUCIBLE_PREFIX := .

# Valid values: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

# Valid values: release, debug
BUILD_TYPE ?= release

TRACER_NAME ?= tracer.ebpf.$(BUILD_TYPE).$(TARGET_ARCH)

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -target aarch64-linux-gnu
else
TARGET_FLAGS = -target x86_64-linux-gnu
endif

# Use -g to generate the btf section in the resulting binary.
FLAGS=$(TARGET_FLAGS) -g \
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
	-D__SOURCE_DATE_EPOCH__=0 \
	-Xclang -fdebug-prefix-map=$(BUILD_DIR)=$(REPRODUCIBLE_PREFIX) \
	-Xclang -fmacro-prefix-map=$(BUILD_DIR)=$(REPRODUCIBLE_PREFIX)

SRCS := $(wildcard *.ebpf.c)
OBJS := $(SRCS:.c=.$(BUILD_TYPE).$(TARGET_ARCH).o)

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

debug:
	$(MAKE) BUILD_TYPE=debug

amd64:
	$(MAKE) TARGET_ARCH=amd64

arm64:
	$(MAKE) TARGET_ARCH=arm64

errors.h: ../../tools/errors-codegen/errors.json
	go run ../../tools/errors-codegen/main.go bpf $@

%.ebpf.c: errors.h ;

%.ebpf.$(BUILD_TYPE).$(TARGET_ARCH).o: %.ebpf.c
	$(BPF_CLANG) $(FLAGS) -o $@

$(TRACER_NAME): $(OBJS)
	$(BPF_LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	# With the compile flag -g not only the btf section is added to the
	# binary but also additional debug sections. As these debug sections
	# are not relevant for BPF and increase the binary size remove them here.
	$(STRIP) --strip-debug --enable-deterministic-archives $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

lint:
	$(CLANG_FORMAT) -Werror --dry-run -style=file *.[ch]

format:
	$(CLANG_FORMAT) -i -style=file *.[ch]

clean:
	rm -f *.o
