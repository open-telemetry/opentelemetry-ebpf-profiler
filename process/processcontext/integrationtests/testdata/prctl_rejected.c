// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

int __real_prctl(int option, ...);

// Models a publisher whose PR_SET_VMA is rejected before the kernel reads the
// name, leaving its page unpopulated. The hook can then only recognize the
// context through its header.
int __wrap_prctl(int option, ...) {
  va_list args;
  va_start(args, option);
  unsigned long arg2 = va_arg(args, unsigned long);
  unsigned long arg3 = va_arg(args, unsigned long);
  unsigned long arg4 = va_arg(args, unsigned long);
  unsigned long arg5 = va_arg(args, unsigned long);
  va_end(args);

  if (option != PR_SET_VMA) {
    return __real_prctl(option, arg2, arg3, arg4, arg5);
  }

  // seccomp still enters the kernel, so sys_exit_prctl fires.
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_VMA, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };
  if (__real_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ||
      __real_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == -1) {
    perror("install PR_SET_VMA seccomp filter");
    exit(EXIT_FAILURE);
  }

  // Never touched, so it reads as zeros if the hook ever manages to read it.
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void *name = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (name == MAP_FAILED) {
    perror("map prctl name");
    exit(EXIT_FAILURE);
  }

  int result = __real_prctl(option, arg2, arg3, arg4, name);
  if (result != -1 || errno != EPERM) {
    fprintf(stderr, "PR_SET_VMA was not rejected\n");
    exit(EXIT_FAILURE);
  }
  munmap(name, page_size);
  errno = EPERM;
  return result;
}
