// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Example application that uses vfork() to test unwinding from the child
// process.
//
// cc -O2 -g -o vfork vfork.c

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void trigger_coredump() {
  // Send SIGILL to ourselves to trigger a coredump.
  // In a vfork child, this will capture the state while the parent is blocked.
  kill(getpid(), SIGILL);
}

void child_func() { trigger_coredump(); }

void parent_func() {
  pid_t pid = vfork();
  if (pid == 0) {
    // Child process
    child_func();
    _exit(0);
  } else if (pid > 0) {
    // Parent process
    printf("Child finished\n");
  } else {
    perror("vfork");
  }
}

int main() {
  parent_func();
  return 0;
}
