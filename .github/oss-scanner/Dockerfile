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

# Fixture setup must succeed so the scanner has the inputs needed to run tests offline.
RUN make test-deps

# Run both suites independently while there is network, downloading the coredump modules into
# tools/coredump/modulecache and warming the Go build cache. Test failures do not abort the build;
# warnings are recorded in the log as well as printed in the build output. Keep the log outside /src
# to keep the checkout clean. Tests tagged integration or host_integration are not run here.
RUN CGO_ENABLED=1 go test -tags osusergo,netgo ./... > /opt/oss-scanner-test.log 2>&1 \
    || echo "WARNING: root module tests failed, see /opt/oss-scanner-test.log" | tee -a /opt/oss-scanner-test.log
RUN CGO_ENABLED=1 go test -C tools/coredump -timeout 60m -tags osusergo,netgo ./... >> /opt/oss-scanner-test.log 2>&1 \
    || echo "WARNING: coredump tests failed, see /opt/oss-scanner-test.log" | tee -a /opt/oss-scanner-test.log

# The scan has no network. Fail fast instead of waiting on proxy timeouts if something was missed above.
ENV GOPROXY=off \
    GOTOOLCHAIN=local
