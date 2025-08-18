#include <stdint.h>

typedef uintptr_t some_typedef;

struct some_struct {
  uint64_t some_array[8];
  uint64_t some_int;
};

int main(int argc, char *argv[]) {
  struct some_struct _my_struct;
  some_typedef _my_typedef;
  return 0;
}
