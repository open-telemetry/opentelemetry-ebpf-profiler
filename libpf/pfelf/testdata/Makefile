.PHONY: all

CC ?= cc
OBJCOPY ?= objcopy

BINARIES=fixed-address \
	go-binary \
	without-debug-syms

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

without-debug-syms: test.c
	$(CC) $< -s -o $@

fixed-address: fixed-address.c fixed-address.ld
	# The following command will likely print a warning (about a missing -T option), which should be ignored.
	# Removing the warning would require passing a fully-fledged linker script to bypass gcc's default.
	$(CC) $^ -o $@

go-binary: gotest.go
	go build -o go-binary -ldflags "-w -s" gotest.go

