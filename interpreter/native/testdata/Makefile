.PHONY: all clean

CC ?= cc

all: testbin testbin-dynsym

testbin: test.c
	$(CC) -o $@ $<

# Stripped of .symtab; -rdynamic exports the functions to .dynsym.
testbin-dynsym: test.c
	$(CC) -rdynamic -o $@ $<
	strip $@

clean:
	rm -f testbin testbin-dynsym
