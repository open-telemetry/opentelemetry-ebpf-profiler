#ifdef HAS_TBSS
#ifdef TBSS_ALIGN
#define ALIGNMENT __attribute__((aligned(32)))
#else
#define ALIGNMENT
#endif
int __thread ALIGNMENT tbss = 0;

int get_tbss()
{
  return tbss;
}
#undef ALIGNMENT
#endif

#ifdef HAS_TDATA
#ifdef TDATA_ALIGN
#define ALIGNMENT __attribute__((aligned(32)))
#else
#define ALIGNMENT
#endif
int __thread ALIGNMENT tdata = 42;

int get_tdata()
{
  return tdata;
}

#undef ALIGNMENT
#endif


#include <unistd.h>

int main()
{
  for (;;)
    sleep(1);
}
