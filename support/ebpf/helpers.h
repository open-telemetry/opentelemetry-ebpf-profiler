// Provide helpers for the eBPF code.

#ifndef OPTI_HELPERS_H
#define OPTI_HELPERS_H

// Macros for BPF program type and context handling.
#ifdef EXTERNAL_TRIGGER
#define BPF_PROBE(name) SEC("kprobe/"#name)
#else
#define BPF_PROBE(name) SEC("perf_event/"#name)
#endif

#endif // OPTI_HELPERS_H