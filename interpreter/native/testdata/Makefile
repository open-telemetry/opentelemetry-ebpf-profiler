CC ?= cc

all: testbin-symtab testbin-dynsym

# -rdynamic exports the functions to .dynsym.
testbin-symtab: test.c
	$(CC) -rdynamic -o $@ $<

# Stripped of .symtab.
testbin-dynsym: testbin-symtab
	strip -o $@ $<

clean:
	rm -f testbin-symtab testbin-dynsym

.PHONY: all clean
