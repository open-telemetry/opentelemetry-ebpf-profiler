// Provide helpers for the eBPF code.

#ifndef OPTI_HELPERS_H
#define OPTI_HELPERS_H

// Macros for BPF program type and context handling.
#ifdef EXTERNAL_TRIGGER
#define BPF_PROBE(name) SEC("kprobe/"#name)
#define BPF_CONTEXT struct pt_regs *ctx
#define GET_REGS(ctx) (ctx)
#else
#define BPF_PROBE(name) SEC("perf_event/"#name)
#define BPF_CONTEXT struct bpf_perf_event_data *ctx
#define GET_REGS(ctx) ((struct pt_regs *)&ctx->regs)
#endif

#endif // OPTI_HELPERS_H