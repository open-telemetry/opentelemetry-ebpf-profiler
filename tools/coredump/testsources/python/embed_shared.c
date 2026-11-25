// Embeds a shared libpython and burns CPU in Python code.
//
// Before running the CPU burning script, a background thread is started that
// keeps sleeping and therefore spends most of its time with the GIL released.
// This allows coredumps to cover unwinding of threads that hold the GIL as well
// as threads that released it.

#ifndef USE_DLOPEN
  #define PY_SSIZE_T_CLEAN
  #include <Python.h>
#endif

#include <stdio.h>
#include <stdlib.h>

static const char script[] = "def recur_fibo(n):\n"
                             "    if n <= 1:\n"
                             "        return n\n"
                             "    return recur_fibo(n - 1) + recur_fibo(n - 2)\n"
                             "\n"
                             "while True:\n"
                             "    print(recur_fibo(30), flush=True)\n";

// Started in a separate PyRun_SimpleString call, so the line numbers of script
// stay stable.
static const char gil_released_script[] = "import threading\n"
                                          "import time\n"
                                          "\n"
                                          "def sleeps_without_gil():\n"
                                          "    while True:\n"
                                          "        time.sleep(1)\n"
                                          "\n"
                                          "def calls_sleep():\n"
                                          "    sleeps_without_gil()\n"
                                          "\n"
                                          "threading.Thread(target=calls_sleep, daemon=True).start()\n";

#ifdef USE_DLOPEN
  #include <dlfcn.h>

int main(int argc, char **argv)
{
  // The Makefile builds in the path of the libpython it found as LIBPYTHON.
  const char *path = argc > 1 ? argv[1] : NULL;
  #ifdef LIBPYTHON
  if (!path) {
    path = LIBPYTHON;
  }
  #endif
  if (!path) {
    fprintf(stderr, "usage: %s /path/to/libpython3.X.so\n", argv[0]);
    return 1;
  }
  void *lib = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
  if (!lib) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 1;
  }
  void (*py_initialize)(void)          = (void (*)(void))dlsym(lib, "Py_Initialize");
  int (*py_run_simple_string)(const char *) =
    (int (*)(const char *))dlsym(lib, "PyRun_SimpleString");
  if (!py_initialize || !py_run_simple_string) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 1;
  }
  py_initialize();
  if (py_run_simple_string(gil_released_script)) {
    return EXIT_FAILURE;
  }
  return py_run_simple_string(script) ? EXIT_FAILURE : EXIT_SUCCESS;
}
#else
int main(void)
{
  Py_Initialize();
  if (PyRun_SimpleString(gil_released_script)) {
    return EXIT_FAILURE;
  }
  return PyRun_SimpleString(script) ? EXIT_FAILURE : EXIT_SUCCESS;
}
#endif
