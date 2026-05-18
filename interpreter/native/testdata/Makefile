.PHONY: all clean

CC ?= cc

all: testbin

testbin: test.c
	$(CC) -o $@ $<

clean:
	rm -f testbin
