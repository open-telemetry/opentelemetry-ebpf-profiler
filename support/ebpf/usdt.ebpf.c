#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"
#include "usdt.h"

#ifndef BPF_USDT_MAX_SPEC_CNT
  #define BPF_USDT_MAX_SPEC_CNT 256
#endif

struct usdt_specs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct bpf_usdt_spec);
  __uint(max_entries, BPF_USDT_MAX_SPEC_CNT);
} __bpf_usdt_specs SEC(".maps");

// Dummy probe to reference USDT maps so they're not considered unreferenced during loading.
// This ensures the maps are available for actual USDT probe programs to use.
// This function is never actually attached, it just ensures the maps are loaded.
SEC("uprobe/usdt_dummy")
int usdt_dummy_probe(UNUSED struct pt_regs *ctx)
{
  u32 spec_id_key            = 0;
  struct bpf_usdt_spec *spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id_key);
  (void)spec; // Reference the spec to avoid unused variable warning
  return 0;
}
