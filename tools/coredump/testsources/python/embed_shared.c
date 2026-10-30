// Embeds a shared libpython and burns CPU in Python code.

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
  return py_run_simple_string(script) ? EXIT_FAILURE : EXIT_SUCCESS;
}
#else
int main(void)
{
  Py_Initialize();
  return PyRun_SimpleString(script) ? EXIT_FAILURE : EXIT_SUCCESS;
}
#endif
