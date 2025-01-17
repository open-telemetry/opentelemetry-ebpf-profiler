.PHONY: all all-common clean ebpf generate test test-deps protobuf docker-image agent legal \
	integration-test-binaries codespell lint linter-version debug debug-agent ebpf-profiler

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

MAKEFLAGS += -j$(shell nproc)

ifneq ($(strip $(BASE_IMAGE)),)
$(info BASE_IMAGE is $(BASE_IMAGE))
endif

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
	@rm -rf go/pkg go/.cache .cache

generate:
	GOARCH=$(NATIVE_ARCH) go generate ./...

ebpf:
	$(MAKE) $(EBPF_FLAGS) -C support/ebpf

ebpf-profiler: generate ebpf
	go build $(GO_FLAGS) -tags $(GO_TAGS)

PROTOC_GEN_VERSION = "v1.31.0"
PROTOC_GRPC_VERSION = "v1.3.0"
GOLANGCI_LINT_VERSION = "v1.60.1"
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
	golangci-lint version
	golangci-lint run

linter-version:
	@echo golangci-lint version: $(GOLANGCI_LINT_VERSION)
	@echo porto version: $(PORTO_VERSION)

.PHONY: vanity-import-check
vanity-import-check:
	@porto --include-internal -l . || ( echo "(run: make vanity-import-fix)"; exit 1 )

.PHONY: vanity-import-fix
vanity-import-fix: $(PORTO)
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

TEST_INTEGRATION_BINARY_DIRS := tracer processmanager/ebpf support

integration-test-binaries: generate ebpf
	$(foreach test_name, $(TEST_INTEGRATION_BINARY_DIRS), \
		(go test -trimpath -c \
			-tags $(GO_TAGS),integration \
			-o ./support/$(subst /,_,$(test_name)).test \
			./$(test_name)) || exit ; \
	)

ifeq ($(strip $(BASE_IMAGE)),)
docker-image:
	  docker build -t profiling-agent -f docker-image/Dockerfile .
else
docker-image:
	  docker build --build-arg image=$(BASE_IMAGE) -t profiling-agent -f docker-image/Dockerfile .
endif

agent:
	docker run -v "$$PWD":/agent -v $(SYSROOT_PATH):/usr/sysroot -it --rm --user $(shell id -u):$(shell id -g) profiling-agent \
	   "make COMPILER_TARGET=$(COMPILER_TARGET) TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)"

debug-agent:
	docker run -v "$$PWD":/agent -v $(SYSROOT_PATH):/usr/sysroot -it --rm --user $(shell id -u):$(shell id -g) profiling-agent \
	   "make COMPILER_TARGET=$(COMPILER_TARGET) TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) debug"

legal:
	@go install github.com/google/go-licenses@latest
	@go-licenses save --force . --save_path=LICENSES
	@./legal/add-non-go.sh legal/non-go-dependencies.json LICENSES

codespell:
	@codespell
