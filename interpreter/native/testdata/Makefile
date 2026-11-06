CC ?= cc

# Stripped of .symtab; -rdynamic exports the functions to .dynsym.
testbin-dynsym: test.c
	$(CC) -rdynamic -o $@ $<
	strip $@

clean:
	rm -f testbin-dynsym

.PHONY: clean
