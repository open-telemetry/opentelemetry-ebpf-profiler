.PHONY: all all-common clean ebpf generate test test-deps protobuf docker-image agent legal \
	integration-test-binaries codespell lint linter-version debug debug-agent ebpf-profiler \
	format-ebpf rust-components rust-targets rust-tests vanity-import-check vanity-import-fix

SHELL := /usr/bin/env bash

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Valid values are: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

ifeq ($(NATIVE_ARCH),$(TARGET_ARCH))
ARCH_PREFIX :=
else ifeq ($(TARGET_ARCH),arm64)
ARCH_PREFIX := aarch64-linux-gnu-
else ifeq ($(TARGET_ARCH),amd64)
ARCH_PREFIX := x86_64-linux-gnu-
else
$(error Unsupported architecture: $(TARGET_ARCH))
endif

export TARGET_ARCH
export CGO_ENABLED = 1
export GOARCH = $(TARGET_ARCH)
export CC = $(ARCH_PREFIX)gcc
export OBJCOPY = $(ARCH_PREFIX)objcopy

BRANCH = $(shell git rev-parse --abbrev-ref HEAD | tr -d '-' | tr '[:upper:]' '[:lower:]')
COMMIT_SHORT_SHA = $(shell git rev-parse --short=8 HEAD)

VERSION ?= v0.0.0
BUILD_TIMESTAMP ?= $(shell date +%s)
REVISION ?= $(BRANCH)-$(COMMIT_SHORT_SHA)

LDFLAGS := -X go.opentelemetry.io/ebpf-profiler/vc.version=$(VERSION) \
	-X go.opentelemetry.io/ebpf-profiler/vc.revision=$(REVISION) \
	-X go.opentelemetry.io/ebpf-profiler/vc.buildTimestamp=$(BUILD_TIMESTAMP) \
	-extldflags=-static

GO_TAGS := osusergo,netgo
EBPF_FLAGS :=

GO_FLAGS := -buildvcs=false -ldflags="$(LDFLAGS)"

MAKEFLAGS += -j$(shell nproc)

all: ebpf-profiler

debug: GO_TAGS := $(GO_TAGS),debugtracer
debug: EBPF_FLAGS += debug
debug: all

# Removes the go build cache and binaries in the current project
clean:
	@go clean -cache -i
	@$(MAKE) -s -C support/ebpf clean
	@rm -f support/*.test
	@chmod -Rf u+w go/ || true
	@rm -rf go .cache
	@cargo clean

generate:
	GOARCH=$(NATIVE_ARCH) go generate ./...
	(cd support && ./generate.sh)

ebpf: generate
	$(MAKE) $(EBPF_FLAGS) -C support/ebpf

ebpf-profiler: generate ebpf rust-components
	go build $(GO_FLAGS) -tags $(GO_TAGS)

rust-targets:
ifeq ($(TARGET_ARCH),arm64)
	rustup target add aarch64-unknown-linux-musl
else ifeq ($(TARGET_ARCH),amd64)
	rustup target add x86_64-unknown-linux-musl
endif

rust-components: rust-targets
ifeq ($(TARGET_ARCH),arm64)
	RUSTFLAGS="--remap-path-prefix $(PWD)=/" cargo build --lib --release --target aarch64-unknown-linux-musl
else ifeq ($(TARGET_ARCH),amd64)
	RUSTFLAGS="--remap-path-prefix $(PWD)=/" cargo build --lib --release --target x86_64-unknown-linux-musl
endif

rust-tests: rust-targets
	cargo test

GOLANGCI_LINT_VERSION = "v1.64.5"
lint: generate vanity-import-check
	$(MAKE) lint -C support/ebpf
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) version
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

format-ebpf:
	$(MAKE) format -C support/ebpf

linter-version:
	@echo $(GOLANGCI_LINT_VERSION)

vanity-import-check:
	@go install github.com/jcchavezs/porto/cmd/porto@latest
	@porto --include-internal -l . || ( echo "(run: make vanity-import-fix)"; exit 1 )

vanity-import-fix: $(PORTO)
	@go install github.com/jcchavezs/porto/cmd/porto@latest
	@porto --include-internal -w .

test: generate ebpf test-deps
	go test $(GO_FLAGS) -tags $(GO_TAGS) ./...

TESTDATA_DIRS:= \
	nativeunwind/elfunwindinfo/testdata \
	libpf/pfelf/testdata \
	reporter/testdata

test-deps:
	$(foreach testdata_dir, $(TESTDATA_DIRS), \
		($(MAKE) -C "$(testdata_dir)") || exit ; \
	)

TEST_INTEGRATION_BINARY_DIRS := tracer processmanager/ebpf support go_labels

integration-test-binaries: generate ebpf
# Call it a ".test" even though it isn't to get included into bluebox initramfs
	go build -o ./support/go_labels_canary.test ./go_labels
	$(foreach test_name, $(TEST_INTEGRATION_BINARY_DIRS), \
		(go test -ldflags='-extldflags=-static' -trimpath -c \
			-tags $(GO_TAGS),static_build,integration \
			-o ./support/$(subst /,_,$(test_name)).test \
			./$(test_name)) || exit ; \
	)

docker-image:
	docker build -t otel/opentelemetry-ebpf-profiler-dev -f Dockerfile .

agent:
	docker run -v "$$PWD":/agent -it --rm --user $(shell id -u):$(shell id -g) otel/opentelemetry-ebpf-profiler-dev:latest \
	   "make TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)"

debug-agent:
	docker run -v "$$PWD":/agent -it --rm --user $(shell id -u):$(shell id -g) otel/opentelemetry-ebpf-profiler-dev:latest \
	   "make TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) debug"

legal:
	@go install github.com/google/go-licenses@latest
	@go-licenses save --force . --save_path=LICENSES
	@./legal/add-non-go.sh legal/non-go-dependencies.json LICENSES

codespell:
	@codespell
