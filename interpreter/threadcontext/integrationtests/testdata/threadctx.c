// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Test program that defines a TLS variable matching what the threadcontext
// interpreter looks for. Used to test TLS offset calculation for static TLS
// (initial-exec model in executables).

#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "threadctx_lib.h"

#ifdef USE_DLOPEN
    #include <dlfcn.h>
    #include <stdio.h>
    #include <stdlib.h>


    typedef void (*init_thread_context_t)(size_t);
    typedef void (*update_thread_context_t)(uint64_t, uint64_t, uint64_t, attribute_t *, size_t);
    typedef void (*burn_t)(int);

    init_thread_context_t init_thread_context;
    update_thread_context_t update_thread_context;
    burn_t burn;

    static int load_lib(const char *libname) {
        void *handle = dlopen(libname, RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }

        init_thread_context = dlsym(handle, "init_thread_context");
        if (!init_thread_context) {
            fprintf(stderr, "dlsym failed: %s\n", dlerror());
            return 1;
        }

        update_thread_context = dlsym(handle, "update_thread_context");
        if (!update_thread_context) {
            fprintf(stderr, "dlsym failed: %s\n", dlerror());
            return 1;   
        }

        burn = dlsym(handle, "burn");
        if (!burn) {
            fprintf(stderr, "dlsym failed: %s\n", dlerror());
            return 1;
        }

        return 0;
    }
#endif

// Busy loop that can be profiled. Runs until SIGTERM.
static volatile int running = 1;

void handle_sigterm(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
#ifdef USE_DLOPEN
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path-to-test_tls_lib.so>\n", argv[0]);
        return 1;
    }
    if (load_lib(argv[1])) {
        fprintf(stderr, "Failed to load library\n");
        return 1;
    }
#endif

    signal(SIGTERM, handle_sigterm);
    init_thread_context(128);

    const uint64_t trace_id_lo = 0x1234567890abcdef;
    const uint64_t trace_id_hi = 0xfedcba9876543210;
    const uint64_t span_id = 0x1234;

    attribute_t attrs[] = {
        {2, 5, "a"},
        {1, 5, "ab"},
        {0, 5, "abc"},
    };

    // Burn CPU so the profiler can sample us.
    while (running) {
        update_thread_context(span_id, trace_id_lo, trace_id_hi, attrs, sizeof(attrs) / sizeof(attrs[0]));
        burn(10);        
    }

    return 0;
}
