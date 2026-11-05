.PHONY: all

BINARIES=helloworld \
	helloworld.pie \
	helloworld.stripped.pie \
	helloworld.arm64 \
	helloworld.linkexternal \
	helloworld.linkexternal.stripped \
	libdebuglink.so

# Use the default go executable if it is not specified otherwise.
GO_BINARY ?= go

all: $(BINARIES)

clean:
	rm -f $(BINARIES) libdebuglink.so.debug

helloworld:
	$(GO_BINARY) build -o $@ helloworld.go

helloworld.pie:
	$(GO_BINARY) build -buildmode=pie -o $@ helloworld.go

helloworld.stripped.pie:
	$(GO_BINARY) build -buildmode=pie -ldflags="-s -w" -o $@ helloworld.go

helloworld.arm64:
	GOARCH=arm64 $(GO_BINARY) build -o $@ helloworld.go

helloworld.linkexternal:
	CGO_ENABLED=1 GOTOOLCHAIN=go1.26.7 $(GO_BINARY) build -ldflags="-linkmode=external" -o $@ helloworld.go

helloworld.linkexternal.stripped: helloworld.linkexternal
	objcopy -S $< $@

# libdebuglink.so has a few functions with .eh_frame, and debug_frame_only has
# unwind info only in the .debug_frame of the .gnu_debuglink file
# libdebuglink.so.debug.
libdebuglink.so: debuglink-ehframe.c debuglink-debugframe.c
	$(CC) -O0 -fPIC -fasynchronous-unwind-tables -c debuglink-ehframe.c -o debuglink-ehframe.o
	$(CC) -O0 -fPIC -g -fno-asynchronous-unwind-tables -fno-unwind-tables \
		-c debuglink-debugframe.c -o debuglink-debugframe.o
	$(CC) -shared -nostdlib -Wl,--build-id=none -Wl,-z,undefs -o $@.full \
		debuglink-ehframe.o debuglink-debugframe.o
	objcopy --only-keep-debug $@.full $@.debug
	objcopy --strip-debug --add-gnu-debuglink=$@.debug $@.full $@
	rm -f $@.full debuglink-ehframe.o debuglink-debugframe.o
