.PHONY: all all-common binary clean ebpf generate test test-deps protobuf docker-image agent legal \
	integration-test-binaries codespell lint linter-version

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

LDFLAGS := -X github.com//open-telemetry/opentelemetry-ebpf-profiler/vc.version=$(VERSION) \
	-X github.com/open-telemetry/opentelemetry-ebpf-profiler/vc.revision=$(REVISION) \
	-X github.com/open-telemetry/opentelemetry-ebpf-profiler/vc.buildTimestamp=$(BUILD_TIMESTAMP) \
	-extldflags=-static

GO_FLAGS := -buildvcs=false -ldflags="$(LDFLAGS)" -tags osusergo,netgo

all: generate ebpf binary

# Removes the go build cache and binaries in the current project
clean:
	@go clean -cache -i
	@$(MAKE) -s -C support/ebpf clean
	@rm -f support/*.test
	@chmod -Rf u+w go/ || true
	@rm -rf go .cache

generate:
	go generate ./...

binary:
	go build $(GO_FLAGS)

ebpf:
	$(MAKE) -j$(shell nproc) -C support/ebpf

GOLANGCI_LINT_VERSION = "v1.60.1"
lint: generate
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) version
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

linter-version:
	@echo $(GOLANGCI_LINT_VERSION)

test: generate ebpf test-deps
	go test $(GO_FLAGS) ./...

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
		(go test -ldflags='-extldflags=-static' -trimpath -c \
			-tags osusergo,netgo,static_build,integration \
			-o ./support/$(subst /,_,$(test_name)).test \
			./$(test_name)) || exit ; \
	)

docker-image:
	docker build -t profiling-agent -f Dockerfile .

agent:
	docker run -v "$$PWD":/agent -it --rm --user $(shell id -u):$(shell id -g) profiling-agent \
	   "make TARGET_ARCH=$(TARGET_ARCH) VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)"

legal:
	@go install github.com/google/go-licenses@latest
	@go-licenses save --force . --save_path=LICENSES
	@./legal/add-non-go.sh legal/non-go-dependencies.json LICENSES

codespell: 
	@codespell
