# Builds embed_shared.c against a shared libpython.

PY_VERSION ?= 3.15

PYTHON_CONFIG ?= $(shell command -v python$(PY_VERSION)-config 2>/dev/null)
PYTHON_LDFLAGS = $(shell $(PYTHON_CONFIG) --ldflags --embed)
# The shared libpython is in one of the -L directories, which for a distro
# Python is not $(PYTHON_CONFIG) --prefix/lib but e.g. /usr/lib/<triplet>.
LIBPYTHON = $(firstword $(wildcard $(addsuffix /libpython$(PY_VERSION).so.1.0, \
	$(patsubst -L%,%,$(filter -L%,$(PYTHON_LDFLAGS))))))
LIBPYTHON_DIR = $(patsubst %/,%,$(dir $(LIBPYTHON)))
CFLAGS ?= -O0 -g -Wall

all: embed_shared embed_shared_dlopen

check-python:
	@if [ -z "$(PYTHON_CONFIG)" ] || ! $(PYTHON_CONFIG) --prefix >/dev/null 2>&1; then \
		echo "python$(PY_VERSION)-config not found: install Python $(PY_VERSION)" \
			"or set PYTHON_CONFIG" >&2; \
		exit 1; \
	fi
	@if [ -z "$(LIBPYTHON)" ]; then \
		echo "libpython$(PY_VERSION).so.1.0 not found in the -L directories of" \
			"$(PYTHON_CONFIG) --ldflags --embed: Python must be built with --enable-shared" >&2; \
		exit 1; \
	fi

embed_shared: embed_shared.c | check-python
	$(CC) $(CFLAGS) -o $@ $< $(shell $(PYTHON_CONFIG) --includes) \
		$(PYTHON_LDFLAGS) -Wl,-rpath,$(LIBPYTHON_DIR)

# LIBPYTHON is built in as the default library to dlopen.
embed_shared_dlopen: embed_shared.c | check-python
	$(CC) $(CFLAGS) -DUSE_DLOPEN -DLIBPYTHON='"$(LIBPYTHON)"' -o $@ $< -ldl

run: embed_shared
	./embed_shared

run-dlopen: embed_shared_dlopen
	./embed_shared_dlopen

clean:
	rm -f embed_shared embed_shared_dlopen

.PHONY: all check-python run run-dlopen clean
