#ifndef OPTI_BPF_MAP_H
#define OPTI_BPF_MAP_H

// bpf_map_def is a custom struct we use to define eBPF maps. It is not used by
// the kernel, but by the ebpf loader (kernel tools, gobpf, cilium-ebpf, etc.).
// This version matches with cilium-ebpf.

typedef struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int pinning;
} bpf_map_def;

// BTF-style map definition macros from tools/lib/bpf/bpf_helpers.h
#define __uint(name, val)  int(*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name

#endif // OPTI_BPF_MAP_H
