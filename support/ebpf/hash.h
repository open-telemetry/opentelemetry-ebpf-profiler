#ifndef OPTI_HASH_H
#define OPTI_HASH_H

#include "types.h"

#define M 0xc6a4a7935bd1e995LLU

static inline __attribute__((__always_inline__))
u64 clear_or_hash_custom_labels(CustomLabelsArray *lbls, bool clear) {
    u64 h = lbls->len * M;
    u64 *bits = (u64 *)lbls;
#pragma unroll
    for (int i=0; i < sizeof(CustomLabelsArray)/8; i++) {
      if (clear) {
        bits[i] = 0;
      } else {
        h ^= bits[i];
        h *= M;
      }
    }

    return h;
}

static inline __attribute__((__always_inline__))
void clear_custom_labels(CustomLabelsArray *lbls) {
  clear_or_hash_custom_labels(lbls, true);
}

static inline __attribute__((__always_inline__))
u64 hash_custom_labels(CustomLabelsArray *lbls) {
  return clear_or_hash_custom_labels(lbls, false);
}

#endif  // OPTI_HASH_H