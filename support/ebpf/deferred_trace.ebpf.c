#include "bpfdefs.h"
#include "types.h"

// deferred_traces holds completed traces until the probe that requested
// deferred delivery is ready to report them.
struct deferred_traces_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, Trace);
  __uint(max_entries, 1); // A probe replaces this disabled shared instance.
} deferred_traces SEC(".maps");

// A probe can defer delivery for its origin into deferred_traces.
BPF_RODATA_VAR(bool, defer_traces, false)
BPF_RODATA_VAR(u16, deferred_origin_id, 0)
