// Provide helpers for the eBPF code.

#ifndef OPTI_HELPERS_H
#define OPTI_HELPERS_H

// Macros for BPF program type and context handling.
#define DEFINE_DUAL_PROGRAM(name, func)                    \
SEC("perf_event/" #name)                                         \
int name##_perf(struct pt_regs *ctx)                         \
{                                                                        \
    return func(ctx, &perf_progs);                            \
}                                                                        \
                                                                         \
SEC("kprobe/" #name)                                             \
int name##_kprobe(struct pt_regs *ctx)                                   \
{                                                                        \
    return func(ctx, &kprobe_progs);                                                    \
}

#endif // OPTI_HELPERS_H