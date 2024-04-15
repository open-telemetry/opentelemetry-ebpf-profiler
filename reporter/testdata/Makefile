.PHONY: all

CC=gcc
CFLAGS=-Wl,--build-id

all: test

clean:
	rm -f test

test: test.c
	$(CC) $(CFLAGS) $< -g -o $@
