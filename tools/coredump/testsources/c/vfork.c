// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Example application that uses vfork() to test unwinding from the child
// process.
//
// cc -O2 -g -o vfork vfork.c

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

void child_func() {
  // Allow any process to ptrace us (needed for gcore in some environments)
  prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

  printf("Child: PID %d, Parent PID %d. Waiting for signal...\n", getpid(),
         getppid());
  // Wait for gcore to capture us.
  while (1) {
    sleep(1);
  }
}

void parent_func() {
  pid_t pid = vfork();
  if (pid == 0) {
    // Child process
    child_func();
    _exit(0);
  } else if (pid > 0) {
    // Parent process
    // Note: Parent is BLOCKED here until child _exits or execs.
    // So if child loops, parent stays here.
    printf("Parent: Child PID %d finished\n", pid);
  } else {
    perror("vfork");
  }
}

int main() {
  parent_func();
  return 0;
}
