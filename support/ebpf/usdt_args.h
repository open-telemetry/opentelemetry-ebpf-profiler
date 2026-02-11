// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef OPTI_USDT_ARGS_H
#define OPTI_USDT_ARGS_H

#include "bpfdefs.h"
#include "usdt.h"

// Forward declarations for USDT maps (defined in usdt.ebpf.c)
extern struct usdt_specs_t __bpf_usdt_specs;

// Helper to get the offset into pt_regs for a given register ID
// This returns the byte offset that can be used with bpf_probe_read_kernel
static EBPF_INLINE int __bpf_usdt_get_reg_off(u8 reg_id)
{
#if defined(__x86_64__)
  switch (reg_id) {
  case BPF_USDT_REG_RAX: return __builtin_offsetof(struct pt_regs, ax);
  case BPF_USDT_REG_RBX: return __builtin_offsetof(struct pt_regs, bx);
  case BPF_USDT_REG_RCX: return __builtin_offsetof(struct pt_regs, cx);
  case BPF_USDT_REG_RDX: return __builtin_offsetof(struct pt_regs, dx);
  case BPF_USDT_REG_RSI: return __builtin_offsetof(struct pt_regs, si);
  case BPF_USDT_REG_RDI: return __builtin_offsetof(struct pt_regs, di);
  case BPF_USDT_REG_RBP: return __builtin_offsetof(struct pt_regs, bp);
  case BPF_USDT_REG_RSP: return __builtin_offsetof(struct pt_regs, sp);
  case BPF_USDT_REG_R8: return __builtin_offsetof(struct pt_regs, r8);
  case BPF_USDT_REG_R9: return __builtin_offsetof(struct pt_regs, r9);
  case BPF_USDT_REG_R10: return __builtin_offsetof(struct pt_regs, r10);
  case BPF_USDT_REG_R11: return __builtin_offsetof(struct pt_regs, r11);
  case BPF_USDT_REG_R12: return __builtin_offsetof(struct pt_regs, r12);
  case BPF_USDT_REG_R13: return __builtin_offsetof(struct pt_regs, r13);
  case BPF_USDT_REG_R14: return __builtin_offsetof(struct pt_regs, r14);
  case BPF_USDT_REG_R15: return __builtin_offsetof(struct pt_regs, r15);
  case BPF_USDT_REG_RIP: return __builtin_offsetof(struct pt_regs, ip);
  default: return -1;
  }
#elif defined(__aarch64__)
  switch (reg_id) {
  case BPF_USDT_REG_X0: return __builtin_offsetof(struct pt_regs, regs[0]);
  case BPF_USDT_REG_X1: return __builtin_offsetof(struct pt_regs, regs[1]);
  case BPF_USDT_REG_X2: return __builtin_offsetof(struct pt_regs, regs[2]);
  case BPF_USDT_REG_X3: return __builtin_offsetof(struct pt_regs, regs[3]);
  case BPF_USDT_REG_X4: return __builtin_offsetof(struct pt_regs, regs[4]);
  case BPF_USDT_REG_X5: return __builtin_offsetof(struct pt_regs, regs[5]);
  case BPF_USDT_REG_X6: return __builtin_offsetof(struct pt_regs, regs[6]);
  case BPF_USDT_REG_X7: return __builtin_offsetof(struct pt_regs, regs[7]);
  case BPF_USDT_REG_X8: return __builtin_offsetof(struct pt_regs, regs[8]);
  case BPF_USDT_REG_X9: return __builtin_offsetof(struct pt_regs, regs[9]);
  case BPF_USDT_REG_X10: return __builtin_offsetof(struct pt_regs, regs[10]);
  case BPF_USDT_REG_X11: return __builtin_offsetof(struct pt_regs, regs[11]);
  case BPF_USDT_REG_X12: return __builtin_offsetof(struct pt_regs, regs[12]);
  case BPF_USDT_REG_X13: return __builtin_offsetof(struct pt_regs, regs[13]);
  case BPF_USDT_REG_X14: return __builtin_offsetof(struct pt_regs, regs[14]);
  case BPF_USDT_REG_X15: return __builtin_offsetof(struct pt_regs, regs[15]);
  case BPF_USDT_REG_X16: return __builtin_offsetof(struct pt_regs, regs[16]);
  case BPF_USDT_REG_X17: return __builtin_offsetof(struct pt_regs, regs[17]);
  case BPF_USDT_REG_X18: return __builtin_offsetof(struct pt_regs, regs[18]);
  case BPF_USDT_REG_X19: return __builtin_offsetof(struct pt_regs, regs[19]);
  case BPF_USDT_REG_X20: return __builtin_offsetof(struct pt_regs, regs[20]);
  case BPF_USDT_REG_X21: return __builtin_offsetof(struct pt_regs, regs[21]);
  case BPF_USDT_REG_X22: return __builtin_offsetof(struct pt_regs, regs[22]);
  case BPF_USDT_REG_X23: return __builtin_offsetof(struct pt_regs, regs[23]);
  case BPF_USDT_REG_X24: return __builtin_offsetof(struct pt_regs, regs[24]);
  case BPF_USDT_REG_X25: return __builtin_offsetof(struct pt_regs, regs[25]);
  case BPF_USDT_REG_X26: return __builtin_offsetof(struct pt_regs, regs[26]);
  case BPF_USDT_REG_X27: return __builtin_offsetof(struct pt_regs, regs[27]);
  case BPF_USDT_REG_X28: return __builtin_offsetof(struct pt_regs, regs[28]);
  case BPF_USDT_REG_X29: return __builtin_offsetof(struct pt_regs, regs[29]); // FP
  case BPF_USDT_REG_X30: return __builtin_offsetof(struct pt_regs, regs[30]); // LR
  case BPF_USDT_REG_SP: return __builtin_offsetof(struct pt_regs, sp);
  case BPF_USDT_REG_PC: return __builtin_offsetof(struct pt_regs, pc);
  default: return -1;
  }
#else
  #error "Unsupported architecture for USDT"
#endif
}

// Helper to read register value from pt_regs based on register ID
// Uses bpf_probe_read_kernel to safely read from the context pointer,
// avoiding BPF verifier issues with modified context pointers
static EBPF_INLINE int __bpf_usdt_get_reg_val(struct pt_regs *ctx, u8 reg_id, unsigned long *val)
{
  int reg_off = __bpf_usdt_get_reg_off(reg_id);
  if (reg_off < 0)
    return -1;

  return bpf_probe_read_kernel(val, sizeof(*val), (void *)ctx + reg_off);
}

// Helper function to get spec_id from context
// The BPF cookie is split: high 32 bits = spec ID, low 32 bits = user cookie
static EBPF_INLINE int __bpf_usdt_spec_id(struct pt_regs *ctx)
{
  u64 cookie = bpf_get_attach_cookie(ctx);
  return (u32)(cookie >> 32);
}

// Helper function to get user cookie from context
// The BPF cookie is split: high 32 bits = spec ID, low 32 bits = user cookie
static EBPF_INLINE UNUSED u32 __bpf_usdt_cookie(struct pt_regs *ctx)
{
  u64 cookie = bpf_get_attach_cookie(ctx);
  return (u32)(cookie & 0xFFFFFFFF);
}

// libbpf-compatible function to fetch USDT arguments
static EBPF_INLINE UNUSED int bpf_usdt_arg(struct pt_regs *ctx, u64 arg_num, long *res)
{
  struct bpf_usdt_spec *spec;
  struct bpf_usdt_arg_spec *arg_spec;
  unsigned long val;
  int err, spec_id;

  *res = 0;

  spec_id = __bpf_usdt_spec_id(ctx);
  if (spec_id < 0)
    return -1;

  spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id);
  if (!spec)
    return -1;

  if (arg_num >= BPF_USDT_MAX_ARG_CNT || arg_num >= spec->arg_cnt)
    return -1;

  arg_spec = &spec->args[arg_num];

  // Read all fields into local variables to help BPF verifier
  u32 arg_type    = arg_spec->arg_type;
  u64 val_off     = arg_spec->val_off;
  u8 reg_id       = arg_spec->reg_id;
  bool arg_signed = arg_spec->arg_signed;
  s8 arg_bitshift = arg_spec->arg_bitshift;

  switch (arg_type) {
  case BPF_USDT_ARG_CONST:
    // Arg is just a constant ("-4@$-9" in USDT arg spec)
    val = val_off;
    break;
  case BPF_USDT_ARG_REG:
    // Arg is in a register (e.g, "8@%rax" in USDT arg spec)
    err = __bpf_usdt_get_reg_val(ctx, reg_id, &val);
    if (err)
      return err;
    break;
  case BPF_USDT_ARG_REG_DEREF:
    // Arg is in memory addressed by register, plus some offset
    err = __bpf_usdt_get_reg_val(ctx, reg_id, &val);
    if (err)
      return err;
    err = bpf_probe_read_user(&val, sizeof(val), (void *)val + val_off);
    if (err)
      return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    val >>= arg_bitshift;
#endif
    break;
  default: return -1;
  }

  // Cast arg from 1, 2, 4, or 8 bytes to final 8 byte size
  val <<= arg_bitshift;
  if (arg_signed)
    val = ((long)val) >> arg_bitshift;
  else
    val = val >> arg_bitshift;
  *res = val;
  return 0;
}

// clang-format off
// Individual argument extraction macros
// Usage: s32 arg0 = bpf_usdt_arg0(ctx);
#define bpf_usdt_arg0(ctx) ({ long _arg; bpf_usdt_arg(ctx, 0, &_arg); _arg; })
#define bpf_usdt_arg1(ctx) ({ long _arg; bpf_usdt_arg(ctx, 1, &_arg); _arg; })
#define bpf_usdt_arg2(ctx) ({ long _arg; bpf_usdt_arg(ctx, 2, &_arg); _arg; })
#define bpf_usdt_arg3(ctx) ({ long _arg; bpf_usdt_arg(ctx, 3, &_arg); _arg; })
#define bpf_usdt_arg4(ctx) ({ long _arg; bpf_usdt_arg(ctx, 4, &_arg); _arg; })
#define bpf_usdt_arg5(ctx) ({ long _arg; bpf_usdt_arg(ctx, 5, &_arg); _arg; })
#define bpf_usdt_arg6(ctx) ({ long _arg; bpf_usdt_arg(ctx, 6, &_arg); _arg; })
#define bpf_usdt_arg7(ctx) ({ long _arg; bpf_usdt_arg(ctx, 7, &_arg); _arg; })
#define bpf_usdt_arg8(ctx) ({ long _arg; bpf_usdt_arg(ctx, 8, &_arg); _arg; })
#define bpf_usdt_arg9(ctx) ({ long _arg; bpf_usdt_arg(ctx, 9, &_arg); _arg; })
#define bpf_usdt_arg10(ctx) ({ long _arg; bpf_usdt_arg(ctx, 10, &_arg); _arg; })
#define bpf_usdt_arg11(ctx) ({ long _arg; bpf_usdt_arg(ctx, 11, &_arg); _arg; })

// The rest of this code is from libbpf
#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a##b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_usdt_args0() ctx
#define ___bpf_usdt_args1(x) ___bpf_usdt_args0(), ({ long _x; bpf_usdt_arg(ctx, 0, &_x); _x; })
#define ___bpf_usdt_args2(x, args...) ___bpf_usdt_args1(args), ({ long _x; bpf_usdt_arg(ctx, 1, &_x); _x; })
#define ___bpf_usdt_args3(x, args...) ___bpf_usdt_args2(args), ({ long _x; bpf_usdt_arg(ctx, 2, &_x); _x; })
#define ___bpf_usdt_args4(x, args...) ___bpf_usdt_args3(args), ({ long _x; bpf_usdt_arg(ctx, 3, &_x); _x; })
#define ___bpf_usdt_args5(x, args...) ___bpf_usdt_args4(args), ({ long _x; bpf_usdt_arg(ctx, 4, &_x); _x; })
#define ___bpf_usdt_args6(x, args...) ___bpf_usdt_args5(args), ({ long _x; bpf_usdt_arg(ctx, 5, &_x); _x; })
#define ___bpf_usdt_args7(x, args...) ___bpf_usdt_args6(args), ({ long _x; bpf_usdt_arg(ctx, 6, &_x); _x; })
#define ___bpf_usdt_args8(x, args...) ___bpf_usdt_args7(args), ({ long _x; bpf_usdt_arg(ctx, 7, &_x); _x; })
#define ___bpf_usdt_args9(x, args...) ___bpf_usdt_args8(args), ({ long _x; bpf_usdt_arg(ctx, 8, &_x); _x; })
#define ___bpf_usdt_args10(x, args...) ___bpf_usdt_args9(args), ({ long _x; bpf_usdt_arg(ctx, 9, &_x); _x; })
#define ___bpf_usdt_args11(x, args...) ___bpf_usdt_args10(args), ({ long _x; bpf_usdt_arg(ctx, 10, &_x); _x; })
#define ___bpf_usdt_args12(x, args...) ___bpf_usdt_args11(args), ({ long _x; bpf_usdt_arg(ctx, 11, &_x); _x; })
#define ___bpf_usdt_args(args...) ___bpf_apply(___bpf_usdt_args, ___bpf_narg(args))(args)

/*
 * BPF_USDT serves the same purpose for USDT handlers as BPF_PROG for
 * tp_btf/fentry/fexit BPF programs and BPF_KPROBE for kprobes.
 * Original struct pt_regs * context is preserved as 'ctx' argument.
 */
#define BPF_USDT(name, args...)						    \
name(struct pt_regs *ctx);						    \
static EBPF_INLINE typeof(name(0))					    \
____##name(UNUSED struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
        _Pragma("GCC diagnostic push")					    \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
        return ____##name(___bpf_usdt_args(args));			    \
        _Pragma("GCC diagnostic pop")					    \
}									    \
static EBPF_INLINE typeof(name(0))					    \
____##name(UNUSED struct pt_regs *ctx, ##args)

#define BPF_USDT_CALL(name, args...) \
        ____##name(___bpf_usdt_args(args))

// clang-format on

#endif // OPTI_USDT_ARGS_H
