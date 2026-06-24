.PHONY: all

# Use the default go executable if it is not specified otherwise.
GO_BINARY ?= go

ifeq ($(TARGET_ARCH),arm64)
ARM64_BINARIES := golabels-nocgo.arm64 \
	golabels-buildinfo-cgo.arm64 \
	golabels-cgo.arm64
endif

BINARIES := $(ARM64_BINARIES)

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

golabels-nocgo.arm64:
	GOARCH=arm64 CGO_ENABLED=0 $(GO_BINARY) build -tags nocgo -o $@ .

golabels-buildinfo-cgo.arm64:
	GOARCH=arm64 CGO_ENABLED=1 $(GO_BINARY) build -tags buildinfocgo -o $@ .

golabels-cgo.arm64:
	GOARCH=arm64 CGO_ENABLED=1 $(GO_BINARY) build -tags withcgo -o $@ .
