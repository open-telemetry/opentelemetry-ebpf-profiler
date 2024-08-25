// Some bits from lua to help with bytecode parsing.

#include <stdint.h>

#define LJ_NOAPI extern
#define LJ_DATA LJ_NOAPI
#define LJ_DATADEF
#define LJ_AINLINE __always_inline

#define MMDEF(_)                                                                 \
    _(index)                                                                     \
    _(newindex)                                                                  \
    _(gc)                                                                        \
    _(mode)                                                                      \
    _(eq)                                                                        \
    _(len) /* Only the above (fast) metamethods are negative cached (max. 8). */ \
    _(lt)                                                                        \
    _(le)                                                                        \
    _(concat)                                                                    \
    _(call) /* The following must be in ORDER ARITH. */                          \
    _(add)                                                                       \
    _(sub)                                                                       \
    _(mul)                                                                       \
    _(div)                                                                       \
    _(mod)                                                                       \
    _(pow)                                                                       \
    _(unm) /* The following are used in the standard libraries. */

typedef enum {
#define MMENUM(name) MM_##name,
  MMDEF(MMENUM)
#undef MMENUM
  MM__MAX,
  MM____ = MM__MAX,
  MM_FAST = MM_len
} MMS;

const char *lj_metanames[] = {
#define MMNAME(name) #name,
  MMDEF(MMNAME)
#undef MMNAME    
  NULL
};

#include "lj_bc.h"
#include "lj_bcdef.h"