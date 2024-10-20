// Provide helpers for the eBPF code.

#ifndef OPTI_HELPERS_H
#define OPTI_HELPERS_H

// Macros for BPF program type and context handling.
#define DEFINE_DUAL_PROGRAM(name, section_name, func)                    \
SEC("perf_event/" #section_name)                                         \
int name##_perf(struct pt_regs *ctx)                         \
{                                                                        \
    return func(ctx);                            \
}                                                                        \
                                                                         \
SEC("kprobe/" #section_name)                                             \
int name##_kprobe(struct pt_regs *ctx)                                   \
{                                                                        \
    return func(ctx);                                                    \
}

#endif // OPTI_HELPERS_H