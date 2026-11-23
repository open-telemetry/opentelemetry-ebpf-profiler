FROM golang:1.26-trixie@sha256:cff05dd6b81c901f2e8249eb6f91c69a60451d0f12c26bfef08e476a85b32d4d

# clang-17 rebuilds the eBPF blobs (support/ebpf/tracer.ebpf.*) so that changes to the C code can be built and checked.
# The coredump tests build the C code with cgo and the test fixtures need a native gcc and binutils.
RUN apt-get update && apt-get install -y --no-install-recommends --no-install-suggests \
      ca-certificates git make gcc g++ libc6-dev pkgconf binutils \
      llvm-17 clang-17 clang-format-17 \
    && rm -rf /var/lib/apt/lists/*

# The scanner expects the checkout inside the image at /src.
COPY . /src
WORKDIR /src

# Builds the eBPF blob from source for the native architecture, generates the collector module and builds the binary.
RUN make otelcol-ebpf-profiler \
    && install -m 0755 otelcol-ebpf-profiler /usr/local/bin/otelcol-ebpf-profiler

# The repository has several Go modules and no go.work. Fetch the ones the build did not touch so their tests work offline.
RUN make go-mod-download \
    && go -C cmd/otelcol-ebpf-profiler mod download

# Build the fixtures, download the coredump modules into tools/coredump/modulecache and cache the compiled test
# binaries while there is network. A failing test does not abort the build. The log is kept outside /src to keep the
# checkout clean. Tests that load eBPF programs need a privileged host and are expected to fail or skip here.
RUN ( make test-deps \
      && CGO_ENABLED=1 go test -tags osusergo,netgo ./... \
      && CGO_ENABLED=1 go test -C tools/coredump -timeout 60m -tags osusergo,netgo ./... ) > /opt/oss-scanner-test.log 2>&1 \
    || echo "WARNING: tests reported failures, see /opt/oss-scanner-test.log"

# The scan has no network. Fail fast instead of waiting on proxy timeouts if something was missed above.
ENV GOPROXY=off \
    GOTOOLCHAIN=local
