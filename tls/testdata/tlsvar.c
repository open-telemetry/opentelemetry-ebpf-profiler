// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Prints where each of the library's thread-locals actually lives, together
// with the thread pointer they are relative to, then blocks so the test can
// locate the same variables from the outside.
//
// Output is one "<name> <tp> <address>" line per variable, hex and unprefixed,
// terminated by a "ready" line.

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifdef USE_DLOPEN
#include <dlfcn.h>
#else
#include "tlsvar_lib.h"
// Weak: only the EXTRA_HIDDEN_TLS_VAR build of the library defines it.
extern long *other_tls_var_addr(void) __attribute__((weak));
#endif

#ifdef __x86_64__
#include <sys/syscall.h>
// From asm/prctl.h, which the musl sysroot does not carry.
#define ARCH_GET_FS 0x1003
#endif

// thread_pointer returns TP as the TLS ABI defines it, which is the value the
// kernel hands eBPF (task->thread.fsbase, task->thread.uw.tp_value).
static uintptr_t thread_pointer(void) {
#ifdef __aarch64__
  uintptr_t tp;
  __asm__("mrs %0, tpidr_el0" : "=r"(tp));
  return tp;
#elif defined(__x86_64__)
  // rdfsbase needs FSGSBASE enabled for userspace, so ask the kernel instead.
  uintptr_t tp = 0;
  if (syscall(SYS_arch_prctl, ARCH_GET_FS, &tp) != 0) {
    return 0;
  }
  return tp;
#else
#error unsupported architecture
#endif
}

typedef long *(*addr_fn)(void);

int main(int argc, char **argv) {
  static const char *const names[] = {"tls_var", "other_tls_var"};
  addr_fn fns[2] = {0};

#ifdef USE_DLOPEN
  if (argc < 2) {
    fprintf(stderr, "usage: %s <library>\n", argv[0]);
    return 1;
  }
  void *lib = dlopen(argv[1], RTLD_NOW);
  if (lib == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 1;
  }
  fns[0] = (addr_fn)dlsym(lib, "tls_var_addr");
  fns[1] = (addr_fn)dlsym(lib, "other_tls_var_addr");
  if (fns[0] == NULL) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror());
    return 1;
  }
#else
  (void)argc;
  (void)argv;
  fns[0] = tls_var_addr;
  fns[1] = other_tls_var_addr;
#endif

  for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
    if (fns[i] == NULL) {
      continue;
    }
    printf("%s %lx %lx\n", names[i], (unsigned long)thread_pointer(),
           (unsigned long)(uintptr_t)fns[i]());
  }
  puts("ready");
  fflush(stdout);

  // Hold the resolved TLS state for the test to inspect.
  pause();
  return 0;
}
