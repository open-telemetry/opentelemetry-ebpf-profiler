.PHONY: all all-common binary clean ebpf generate test test-deps protobuf docker-image agent legal \
	integration-test-binaries

SHELL := /usr/bin/env bash

BRANCH = $(shell git rev-parse --abbrev-ref HEAD | tr -d '-' | tr '[:upper:]' '[:lower:]')
COMMIT_SHORT_SHA = $(shell git rev-parse --short=8 HEAD)

VERSION ?= v0.0.0
BUILD_TIMESTAMP ?= $(shell date +%s)
REVISION ?= $(BRANCH)-$(COMMIT_SHORT_SHA)

VC_LDFLAGS := -X github.com/elastic/otel-profiling-agent/vc.version=$(VERSION) \
	-X github.com/elastic/otel-profiling-agent/vc.revision=$(REVISION) \
	-X github.com/elastic/otel-profiling-agent/vc.buildTimestamp=$(BUILD_TIMESTAMP)

all: generate ebpf binary

# Removes the go build cache and binaries in the current project
clean:
	@go clean -cache -i
	@$(MAKE) -s -C support/ebpf clean
	@rm -f support/*.test
	@chmod -Rf u+w go/ || true
	@rm -rf go .cache

generate:
	go install github.com/florianl/bluebox@v0.0.1
	go generate ./...

binary:
	go build -buildvcs=false -ldflags="$(VC_LDFLAGS) -extldflags=-static" -tags osusergo,netgo

ebpf:
	$(MAKE) -j$(shell nproc) -C support/ebpf

lint: generate
	# We don't want to build the tracers here, so we stub them for linting
	touch support/ebpf/tracer.ebpf.x86
	golangci-lint run --timeout 10m

test: generate ebpf test-deps
	go test ./...

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

# Detect native architecture.
UNAME_NATIVE_ARCH:=$(shell uname -m)

ifeq ($(UNAME_NATIVE_ARCH),x86_64)
NATIVE_ARCH:=amd64
else ifneq (,$(filter $(UNAME_NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH:=arm64
else
$(error Unsupported architecture: $(UNAME_NATIVE_ARCH))
endif

docker-image:
	docker build -t profiling-agent --build-arg arch=$(NATIVE_ARCH) -f Dockerfile .

agent:
	docker run -v "$$PWD":/agent -it --rm --user $(shell id -u):$(shell id -g) profiling-agent \
		make VERSION=$(VERSION) REVISION=$(REVISION) BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)

legal:
	@go install go.elastic.co/go-licence-detector@latest
	@go list -m -json $(sort $(shell go list -deps -tags=linux -f "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}" .)) | go-licence-detector \
	  -includeIndirect \
	  -rules legal/rules.json \
	  -depsTemplate=legal/templates/deps.csv.tmpl \
	  -depsOut=deps.profiling-agent.csv
	@./legal/append-non-go-info.sh legal/non-go-dependencies.json deps.profiling-agent.csv
	@echo "Dependencies license summary (from deps.profiling-agent.csv):"
	@echo "  Count License"
	@tail -n '+2' deps.profiling-agent.csv | cut -d',' -f5 | sort | uniq -c | sort -k1rn
