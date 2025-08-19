.PHONY: pprof pprof_1_23 pprof_1_24 pprof_1_24_cgo clean

# Valid values are: amd64, arm64.
TARGET_ARCH ?= $(GOARCH)
ifeq ($(TARGET_ARCH),arm64)
ARCH_PREFIX := aarch64
else ifeq ($(TARGET_ARCH),amd64)
ARCH_PREFIX := x86_64
else
$(error Unsupported architecture: $(TARGET_ARCH))
endif

export CC = $(TARGET_ARCH)-linux-gnu-gcc

pprof: pprof_1_23 pprof_1_24 pprof_1_24_cgo 

pprof_1_23:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.23.7 go test -C ./pprof -c -trimpath -tags nocgo,integration -o ./../$@

pprof_1_24:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.24.6 go test -C ./pprof -c -trimpath -tags nocgo,integration  -o ./../$@

pprof_1_24_cgo:
	CGO_ENABLED=1 GOTOOLCHAIN=go1.24.6 go test -C ./pprof -c -ldflags '-extldflags "-static"' -trimpath -tags withcgo,integration  -o ./../$@

clean:
	rm pprof_1_*
