#ifndef OPTI_UTIL_H
#define OPTI_UTIL_H

#include "bpfdefs.h"
#include "extmaps.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

// increment_metric increments the value of the given metricID by 1
static inline EBPF_INLINE void increment_metric(u32 metricID)
{
  u64 *count = bpf_map_lookup_elem(&metrics, &metricID);
  if (count) {
    ++*count;
  } else {
    DEBUG_PRINT("Failed to lookup metrics map for metricID %d", metricID);
  }
}

#endif
