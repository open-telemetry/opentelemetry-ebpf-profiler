.PHONY: all all-common clean ebpf generate test test-deps \
	test-junit protobuf docker-image agent legal integration-test-binaries \
	codespell lint linter-version debug debug-agent ebpf-profiler format-ebpf \
	rust-components rust-targets rust-tests vanity-import-check vanity-import-fix

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
ifeq ($(TARGET_ARCH),arm64)
ARCH_PREFIX := aarch64
else ifeq ($(TARGET_ARCH),amd64)
ARCH_PREFIX := x86_64
else
$(error Unsupported architecture: $(TARGET_ARCH))
endif

export TARGET_ARCH
export CGO_ENABLED = 0
export GOARCH = $(TARGET_ARCH)
export CC = $(ARCH_PREFIX)-linux-gnu-gcc
export OBJCOPY = $(ARCH_PREFIX)-linux-gnu-objcopy

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

JUNIT_OUT_DIR ?= /tmp/testresults

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

ebpf-profiler: generate ebpf
	go build $(GO_FLAGS) -tags $(GO_TAGS)

rust-targets:
	rustup target add $(ARCH_PREFIX)-unknown-linux-musl

rust-components: rust-targets
	RUSTFLAGS="--remap-path-prefix $(PWD)=/" cargo build --lib --release --target $(ARCH_PREFIX)-unknown-linux-musl

rust-tests: rust-targets
	cargo test

GOLANGCI_LINT_VERSION = "v2.1.6"
lint: generate vanity-import-check
	$(MAKE) lint -C support/ebpf
	docker run --rm -t -v $$(pwd):/app -w /app golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) sh -c "golangci-lint version && golangci-lint config verify && golangci-lint run --max-issues-per-linter -1 --max-same-issues -1"

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
	# tools/coredump tests build ebpf C-code using CGO to test it against coredumps
	CGO_ENABLED=1 go test $(GO_FLAGS) -tags $(GO_TAGS) ./...

test-junit: generate ebpf test-deps
	mkdir -p $(JUNIT_OUT_DIR)
	go install gotest.tools/gotestsum@latest
	CGO_ENABLED=1 gotestsum --junitfile $(JUNIT_OUT_DIR)/junit.xml -- $(GO_FLAGS) -tags $(GO_TAGS) ./...

# This target isn't called from CI, it doesn't work for cross compile (ie TARGET_ARCH=arm64 on
# amd64) and the CI kernel tests run them already. Useful for local testing.
sudo-golabels-test: integration-test-binaries
	(cd support && sudo ./interpreter_golabels_test.test -test.v)

TESTDATA_DIRS:= \
	nativeunwind/elfunwindinfo/testdata \
	libpf/pfelf/testdata \
	reporter/testdata

test-deps:
	$(foreach testdata_dir, $(TESTDATA_DIRS), \
		($(MAKE) -C "$(testdata_dir)") || exit ; \
	)

TEST_INTEGRATION_BINARY_DIRS := tracer processmanager/ebpf support interpreter/golabels/test

# These binaries are named ".test" to get included into bluebox initramfs
support/golbls_1_23.test: ./interpreter/golabels/test/main.go
	CGO_ENABLED=0 GOTOOLCHAIN=go1.23.7 go build -tags $(GO_TAGS),nocgo -o $@ $<

support/golbls_1_24.test: ./interpreter/golabels/test/main.go
	CGO_ENABLED=0 GOTOOLCHAIN=go1.24.1 go build -tags $(GO_TAGS),nocgo -o $@ $<

support/golbls_cgo.test: ./interpreter/golabels/test/main-cgo.go
	CGO_ENABLED=1 GOTOOLCHAIN=go1.24.1 go build -ldflags '-extldflags "-static"' -tags $(GO_TAGS),usecgo  -o $@ $<

integration-test-binaries: generate ebpf support/golbls_1_23.test support/golbls_1_24.test support/golbls_cgo.test
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

codespell:
	@codespell
