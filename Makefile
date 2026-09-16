.PHONY: all all-common clean ebpf generate generate-collector test test-deps \
	test-junit protobuf docker-image agent test-docker legal integration-test-binaries \
	codespell lint ebpf-profiler format format-ebpf format-go pprof-execs \
	pprof_1_23 pprof_1_24 pprof_1_24_cgo otelcol-ebpf-profiler \
	rust-components rust-targets rust-tests vanity-import-check vanity-import-fix \
	otel-from-tree otel-from-lib

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
COMPILER_TARGET_ARCH := aarch64
else ifeq ($(TARGET_ARCH),amd64)
COMPILER_TARGET_ARCH := x86_64
else
$(error Unsupported architecture: $(TARGET_ARCH))
endif

COMPILER_TARGET ?= $(COMPILER_TARGET_ARCH)-redhat-linux
SYSROOT_PATH ?= /
BUILD_ENV ?= local
ifeq ($(BUILD_ENV),local)
TTY_IT_OPT := -it
else
TTY_IT_OPT :=
endif
BUILD_IMAGE ?= profiling-agent

export CC = clang-17
export COMPILER_TARGET
export CGO_CFLAGS = --sysroot=/usr/sysroot --target=$(COMPILER_TARGET)
export CGO_ENABLED = 1
export CGO_LDFLAGS = -fuse-ld=lld --sysroot=/usr/sysroot
export GOARCH = $(TARGET_ARCH)
export TARGET_ARCH

BRANCH = $(shell git rev-parse --abbrev-ref HEAD | tr -d '-' | tr '[:upper:]' '[:lower:]')
COMMIT_SHORT_SHA = $(shell git rev-parse --short=8 HEAD)

VERSION ?= v0.0.0
BUILD_TIMESTAMP ?= $(shell date +%s)
REVISION ?= $(BRANCH)-$(COMMIT_SHORT_SHA)

LDFLAGS := -X go.opentelemetry.io/ebpf-profiler/vc.version=$(VERSION) \
	-X go.opentelemetry.io/ebpf-profiler/vc.revision=$(REVISION) \
	-X go.opentelemetry.io/ebpf-profiler/vc.buildTimestamp=$(BUILD_TIMESTAMP) \
	\"-extldflags=$(CGO_CFLAGS)\"

GO_TAGS := osusergo,netgo
EBPF_FLAGS :=

GO_FLAGS := -buildvcs=false -ldflags="$(LDFLAGS)"
GO_TOOLS := -modfile=internal/tools/go.mod

MAKEFLAGS += -j$(shell nproc)

ifneq ($(strip $(BASE_IMAGE)),)
$(info BASE_IMAGE is $(BASE_IMAGE))
endif

all: ebpf-profiler

all: ebpf-profiler

# Removes the go build cache and binaries in the current project
clean:
	@go clean -cache -i
	@$(MAKE) -s -C support/ebpf clean
	@chmod -Rf u+w go/ || true
	@rm -rf go/pkg go/.cache .cache support/*.test interpreter/golabels/integrationtests/pprof_1_*
	@rm -f otelcol-ebpf-profiler cmd/otelcol-ebpf-profiler/{*.go,go.mod,go.sum} || true
	@cargo clean

generate:
	GOARCH=$(NATIVE_ARCH) go generate ./...
	(cd support && ./generate.sh)

ebpf: generate
	$(MAKE) $(EBPF_FLAGS) -C support/ebpf

generate-collector:
	GOARCH=$(NATIVE_ARCH) go tool $(GO_TOOLS) builder \
		--skip-compilation=true \
		--config cmd/otelcol-ebpf-profiler/manifest.yaml \
		--output-path cmd/otelcol-ebpf-profiler

ebpf-profiler: ebpf
	go build $(GO_FLAGS) -tags $(GO_TAGS)

PROTOC_GEN_VERSION = "v1.31.0"
PROTOC_GRPC_VERSION = "v1.3.0"
GOLANGCI_LINT_VERSION = "v1.63.4"
PORTO_VERSION = "v0.6.0"

install-grpc-deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GRPC_VERSION)

install-ci-deps:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/jcchavezs/porto/cmd/porto@$(PORTO_VERSION)

install-go-deps: install-grpc-deps install-ci-deps

clean-go-deps: clean
	@rm go/bin/protoc*
	@rm go/bin/porto*
	@rm go/bin/golang*

lint: generate vanity-import-check
	$(MAKE) lint -C support/ebpf
	golangci-lint version
	golangci-lint run
otelcol-ebpf-profiler: ebpf generate-collector
	cd cmd/otelcol-ebpf-profiler/ && go build $(GO_FLAGS) -tags "$(GO_TAGS)" -o ../../$@

# Sets opentelemetry collector modules to be pulled from local source tree.
# This command allows you to make changes to your local checkout of otel core and build
# the collector against those changes without having to push to github.
# The workflow is:
#
# 1. Hack on changes in core (assumed to be checked out in ../opentelemetry-collector from this directory)
# 2. Run `make otel-from-tree` (only need to run it once to remap go modules)
# 3. You can now build collector and it will use your local otel core changes.
# 4. Before committing/pushing your changes, undo by running `make otel-from-lib`.
otel-from-tree: generate-collector
	./cmd/otelcol-ebpf-profiler/otel-from-tree.sh

# Removes local opentelemetry-collector replaces from manifest.yaml.
# (Undoes otel-from-tree.)
otel-from-lib:
	./cmd/otelcol-ebpf-profiler/otel-from-lib.sh

rust-targets:
	rustup target add $(ARCH_PREFIX)-unknown-linux-musl

rust-components: rust-targets
	RUSTFLAGS="--remap-path-prefix $(PWD)=/" cargo build --lib --release --target $(ARCH_PREFIX)-unknown-linux-musl

rust-tests: rust-targets
	cargo test

lint: generate vanity-import-check pprof-execs
	$(MAKE) lint -C support/ebpf
	go tool $(GO_TOOLS) golangci-lint config verify
	# tools/coredump tests require CGO_ENABLED
	CGO_ENABLED=1 go tool $(GO_TOOLS) golangci-lint run --max-issues-per-linter -1 --max-same-issues -1

format: format-go format-ebpf

format-go:
	go tool $(GO_TOOLS) golangci-lint fmt

format-ebpf:
	$(MAKE) format -C support/ebpf

linter-version:
	@echo golangci-lint version: $(GOLANGCI_LINT_VERSION)
	@echo porto version: $(PORTO_VERSION)

vanity-import-check:
	go tool $(GO_TOOLS) porto --skip-dirs "^(LICENSES|go|target).*" --include-internal -l . || ( echo "(run: make vanity-import-fix)"; exit 1 )

vanity-import-fix:
	go tool $(GO_TOOLS) porto --skip-dirs "^(LICENSES|go|target).*" --include-internal -w .

test: generate ebpf test-deps
	# tools/coredump tests build ebpf C-code using CGO to test it against coredumps
	CGO_ENABLED=1 go test $(GO_FLAGS) -tags $(GO_TAGS) ./...

test-junit: generate ebpf test-deps
	mkdir -p $(JUNIT_OUT_DIR)
	CGO_ENABLED=1 go tool $(GO_TOOLS) gotestsum --junitfile $(JUNIT_OUT_DIR)/junit.xml -- $(GO_FLAGS) -tags $(GO_TAGS) ./...

TESTDATA_DIRS:= \
	nativeunwind/elfunwindinfo/testdata \
	libpf/pfelf/testdata \
	reporter/testdata

test-deps:
	$(foreach testdata_dir, $(TESTDATA_DIRS), \
		($(MAKE) -C "$(testdata_dir)") || exit ; \
	)

TEST_INTEGRATION_BINARY_DIRS := tracer processmanager/ebpf kallsyms support interpreter/golabels/integrationtests

pprof-execs: pprof_1_23 pprof_1_24 pprof_1_24_cgo pprof_1_24_cgo_pie pprof_stable pprof_stable_cgo pprof_stable_cgo_pie

pprof_1_23:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.23.7 go test -C ./interpreter/golabels/integrationtests/pprof -c -trimpath -tags $(GO_TAGS),nocgo,integration -o ./../$@

pprof_1_24:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.24.6 go test -C ./interpreter/golabels/integrationtests/pprof -c -trimpath -tags $(GO_TAGS),nocgo,integration -o ./../$@

pprof_1_24_cgo:
	CGO_ENABLED=1 GOTOOLCHAIN=go1.24.6 go test -C ./interpreter/golabels/integrationtests/pprof -c  -trimpath -tags $(GO_TAGS),withcgo,integration -o ./../$@

pprof_1_24_cgo_pie:
	CGO_ENABLED=1 GOTOOLCHAIN=go1.24.6 go test -C ./interpreter/golabels/integrationtests/pprof -c  -trimpath -buildmode=pie -tags $(GO_TAGS),withcgo,integration -o ./../$@

pprof_stable:
	CGO_ENABLED=0 go test -C ./interpreter/golabels/integrationtests/pprof -c -trimpath -tags $(GO_TAGS),nocgo,integration -o ./../$@

pprof_stable_cgo:
	CGO_ENABLED=1 go test -C ./interpreter/golabels/integrationtests/pprof -c  -trimpath -tags $(GO_TAGS),withcgo,integration -o ./../$@

pprof_stable_cgo_pie:
	CGO_ENABLED=1 go test -C ./interpreter/golabels/integrationtests/pprof -c  -trimpath -buildmode=pie -tags $(GO_TAGS),withcgo,integration -o ./../$@

integration-test-binaries: generate ebpf pprof-execs
	$(foreach test_name, $(TEST_INTEGRATION_BINARY_DIRS), \
		(go test -trimpath -c \
			-tags $(GO_TAGS),integration \
			-o ./support/$(subst /,_,$(test_name)).test \
			./$(test_name)) || exit ; \
	)

ifeq ($(strip $(BASE_IMAGE)),)
docker-image:
	  docker build -t $(BUILD_IMAGE) -f docker-image/Dockerfile .
else
docker-image:
	  docker build --build-arg image=$(BASE_IMAGE) -t $(BUILD_IMAGE) -f docker-image/Dockerfile .
endif

agent:
	docker run -v "$$PWD":/agent -v $(SYSROOT_PATH):/usr/sysroot $(TTY_IT_OPT) --rm --user $(shell id -u):$(shell id -g) $(BUILD_IMAGE) \
	   "make COMPILER_TARGET=$(COMPILER_TARGET) TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)"

debug-agent:
	docker run -v "$$PWD":/agent -v $(SYSROOT_PATH):/usr/sysroot $(TTY_IT_OPT) --rm --user $(shell id -u):$(shell id -g) $(BUILD_IMAGE) \
	   "make COMPILER_TARGET=$(COMPILER_TARGET) TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) debug"

test-docker:
	docker run -v "$$PWD":/agent -v $(SYSROOT_PATH):/usr/sysroot $(TTY_IT_OPT) --rm --user $(shell id -u):$(shell id -g) $(BUILD_IMAGE) \
	   "make COMPILER_TARGET=$(COMPILER_TARGET) TARGET_ARCH=$(TARGET_ARCH) test"

legal:
	go tool $(GO_TOOLS) go-licenses save --force . --save_path=LICENSES

codespell:
	@codespell
