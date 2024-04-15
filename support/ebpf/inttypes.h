#ifndef OPTI_INTTYPES_H
#define OPTI_INTTYPES_H

// The kconfig header is required when performing actual eBPF builds but not
// even present in user-mode builds, so we have to make the include conditional.
#if defined(__KERNEL__)
# include <linux/kconfig.h>
#endif

#include <linux/types.h>

// Some test targets (user-mode tests, integration tests) don't have these
// non-underscore types, so we make sure they exist here.
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

#endif // OPTI_INTTYPES_H
