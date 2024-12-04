#include "bpfdefs.h"
#include "frametypes.h"
#include "types.h"
#include "tracemgmt.h"
#include "stackdeltatypes.h"

#ifndef __USER32_CS
  // defined in arch/x86/include/asm/segment.h
  #define GDT_ENTRY_DEFAULT_USER32_CS  4
  #define GDT_ENTRY_DEFAULT_USER_DS    5
  #define __USER32_CS                 (GDT_ENTRY_DEFAULT_USER32_CS*8 + 3)
  #define __USER_DS                   (GDT_ENTRY_DEFAULT_USER_DS*8 + 3)
#endif

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given fileID.
#define STACK_DELTA_BUCKET(X)                                                            \
  bpf_map_def SEC("maps") exe_id_to_##X##_stack_deltas = { \
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,                                                   \
    .key_size = sizeof(u64),                                                             \
    .value_size = sizeof(u32),                                                           \
    .max_entries = 4096,                                                                 \
  };

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);
STACK_DELTA_BUCKET(22);
STACK_DELTA_BUCKET(23);

// Unwind info value for invalid stack delta
#define STACK_DELTA_INVALID (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_INVALID)
#define STACK_DELTA_STOP    (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_STOP)

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
bpf_map_def SEC("maps") unwind_info_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(UnwindInfo),
  // Maximum number of unique stack deltas needed on a system. This is based on
  // normal desktop /usr/bin/* and /usr/lib/*.so having about 9700 unique deltas.
  // Can be increased up to 2^15, see also STACK_DELTA_COMMAND_FLAG.
  .max_entries = 16384,
};

// The number of native frames to unwind per frame-unwinding eBPF program.
#define NATIVE_FRAMES_PER_PROGRAM 4

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
bpf_map_def SEC("maps") interpreter_offsets = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(OffsetRange),
  .max_entries = 32,
};

// Maps fileID and page to information of stack deltas associated with that page.
bpf_map_def SEC("maps") stack_delta_page_to_info = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(StackDeltaPageKey),
  .value_size = sizeof(StackDeltaPageInfo),
  .max_entries = 40000,
};

// This contains the kernel PCs as returned by bpf_get_stackid(). Unfortunately the ebpf
// program cannot read the contents, so we return the stackid in the Trace directly, and
// make the profiling agent read the kernel mode stack trace portion from this map.
bpf_map_def SEC("maps") kernel_stackmap = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(u32),
  .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
  .max_entries = 16*1024,
};

// Record a native frame
static inline __attribute__((__always_inline__))
ErrorCode push_native(Trace *trace, u64 file, u64 line, bool return_address) {
  return _push_with_return_address(trace, file, line, FRAME_MARKER_NATIVE, return_address);
}

#ifdef __aarch64__
// Strips the PAC tag from a pointer.
//
// While all pointers can contain PAC tags, we only apply this function to code pointers, because
// that's where normalization is required to make the stack delta lookups work. Note that if that
// should ever change, we'd need a different mask for the data pointers, because it might diverge
// from the mask for code pointers.
static inline u64 normalize_pac_ptr(u64 ptr) {
  // Retrieve PAC mask from the system config.
  u32 key = 0;
  SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
  if (!syscfg) {
    // Unreachable: array maps are always fully initialized.
    return ptr;
  }

  // Mask off PAC bits. Since we're always applying this to usermode pointers that should have all
  // the high bits set to 0, we don't need to consider the case of having to fill up the resulting
  // hole with 1s (like we'd have to for kernel ptrs).
  ptr &= syscfg->inverse_pac_mask;
  return ptr;
}
#endif

// A single step for the bsearch into the big_stack_deltas array. This is really a textbook bsearch
// step, built in a way to update the value of *lo and *hi. This function will be called repeatedly
// (since we cannot do loops). The return value signals whether the bsearch came to an end / found
// the right element or whether it needs to continue.
static inline __attribute__((__always_inline__))
bool bsearch_step(void* inner_map, u32* lo, u32* hi, u16 page_offset) {
  u32 pivot = (*lo + *hi) >> 1;
  StackDelta *delta = bpf_map_lookup_elem(inner_map, &pivot);
  if (!delta) {
    *hi = 0;
    return false;
  }
  if (page_offset >= delta->addrLow) {
    *lo = pivot + 1;
  } else {
    *hi = pivot;
  }
  return *lo < *hi;
}

// Get the outer map based on the number of stack delta entries.
static inline __attribute__((__always_inline__))
void *get_stack_delta_map(int mapID) {
  switch (mapID) {
  case  8: return &exe_id_to_8_stack_deltas;
  case  9: return &exe_id_to_9_stack_deltas;
  case 10: return &exe_id_to_10_stack_deltas;
  case 11: return &exe_id_to_11_stack_deltas;
  case 12: return &exe_id_to_12_stack_deltas;
  case 13: return &exe_id_to_13_stack_deltas;
  case 14: return &exe_id_to_14_stack_deltas;
  case 15: return &exe_id_to_15_stack_deltas;
  case 16: return &exe_id_to_16_stack_deltas;
  case 17: return &exe_id_to_17_stack_deltas;
  case 18: return &exe_id_to_18_stack_deltas;
  case 19: return &exe_id_to_19_stack_deltas;
  case 20: return &exe_id_to_20_stack_deltas;
  case 21: return &exe_id_to_21_stack_deltas;
  case 22: return &exe_id_to_22_stack_deltas;
  case 23: return &exe_id_to_23_stack_deltas;
  default: return NULL;
  }
}

// Get the stack offset of the given instruction.
static ErrorCode get_stack_delta(UnwindState *state,
                                 int* addrDiff, u32* unwindInfo) {
  u64 exe_id = state->text_section_id;

  // Look up the stack delta page information for this address.
  StackDeltaPageKey key = { };
  key.fileID = state->text_section_id;
  key.page = state->text_section_offset & ~STACK_DELTA_PAGE_MASK;
  DEBUG_PRINT("Look up stack delta for %lx:%lx",
    (unsigned long)state->text_section_id, (unsigned long)state->text_section_offset);
  StackDeltaPageInfo *info = bpf_map_lookup_elem(&stack_delta_page_to_info, &key);
  if (!info) {
    DEBUG_PRINT("Failure to look up stack delta page fileID %lx, page %lx",
                (unsigned long)key.fileID, (unsigned long)key.page);
    state->error_metric = metricID_UnwindNativeErrLookupTextSection;
    return ERR_NATIVE_LOOKUP_TEXT_SECTION;
  }

  void *outer_map = get_stack_delta_map(info->mapID);
  if (!outer_map) {
    DEBUG_PRINT("Failure to look up outer map for text section %lx in mapID %d",
                (unsigned long) exe_id, (int) info->mapID);
    state->error_metric = metricID_UnwindNativeErrLookupStackDeltaOuterMap;
    return ERR_NATIVE_LOOKUP_STACK_DELTA_OUTER_MAP;
  }

  void *inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
  if (!inner_map) {
    DEBUG_PRINT("Failure to look up inner map for text section %lx",
                (unsigned long) exe_id);
    state->error_metric = metricID_UnwindNativeErrLookupStackDeltaInnerMap;
    return ERR_NATIVE_LOOKUP_STACK_DELTA_INNER_MAP;
  }

  // Preinitialize the idx for the index to use for page without any deltas.
  u32 idx = info->firstDelta;
  u16 page_offset = state->text_section_offset & STACK_DELTA_PAGE_MASK;
  if (info->numDeltas) {
    // Page has deltas, so find the correct one to use using binary search.
    u32 lo = info->firstDelta;
    u32 hi = lo + info->numDeltas;

    DEBUG_PRINT("Intervals should be from %lu to %lu (mapID %d)",
      (unsigned long) lo, (unsigned long) hi, (int)info->mapID);

    // Do the binary search, up to 16 iterations. Deltas are paged to 64kB pages.
    // They can contain at most 64kB deltas even if everything is single byte opcodes.
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
      if (!bsearch_step(inner_map, &lo, &hi, page_offset)) {
        break;
      }
    }
    if (i >= 16 || hi == 0) {
      DEBUG_PRINT("Failed bsearch in 16 steps. Corrupt data?");
      state->error_metric = metricID_UnwindNativeErrLookupIterations;
      return ERR_NATIVE_EXCEEDED_DELTA_LOOKUP_ITERATIONS;
    }
    // After bsearch, 'hi' points to the first entry greater than the requested.
    idx = hi;
  }

  // The code above found the first entry with greater address than requested,
  // so it needs to be decremented by one to get the entry with equal-or-less.
  // This makes also the logic work cross-pages: if the first entry in within
  // the page is too large, this actually gets the entry from the previous page.
  idx--;

  StackDelta *delta = bpf_map_lookup_elem(inner_map, &idx);
  if (!delta) {
    state->error_metric = metricID_UnwindNativeErrLookupRange;
    return ERR_NATIVE_LOOKUP_RANGE;
  }

  DEBUG_PRINT("delta index %d, addrLow 0x%x, unwindInfo %d",
    idx, delta->addrLow, delta->unwindInfo);

  // Calculate PC delta from stack delta for merged delta comparison
  int deltaOffset = (int)page_offset - (int)delta->addrLow;
  if (idx < info->firstDelta) {
    // PC is below the first delta of the corresponding page. This means that
    // delta->addrLow contains address relative to one page before the page_offset.
    // Fix up the deltaOffset with this difference of base pages.
    deltaOffset += 1 << STACK_DELTA_PAGE_BITS;
  }

  *addrDiff = deltaOffset;
  *unwindInfo = delta->unwindInfo;

  if (delta->unwindInfo == STACK_DELTA_INVALID) {
    state->error_metric = metricID_UnwindNativeErrStackDeltaInvalid;
    return ERR_NATIVE_STACK_DELTA_INVALID;
  }
  if (delta->unwindInfo == STACK_DELTA_STOP) {
    increment_metric(metricID_UnwindNativeStackDeltaStop);
  }

  return ERR_OK;
}

// unwind_register_address calculates the given expression ('opcode'/'param') to get
// the CFA (canonical frame address, to recover PC and be used in further calculations),
// or the address where a register is stored (FP currently), so that the value of
// the register can be recovered.
//
// Currently the following expressions are supported:
//   1. Not recoverable -> NULL is returned.
//   2. When UNWIND_OPCODEF_DEREF is not set:
//      BASE + param
//   3. When UNWIND_OPCODEF_DEREF is set:
//      *(BASE + preDeref) + postDeref
static inline __attribute__((__always_inline__))
u64 unwind_register_address(UnwindState *state, u64 cfa, u8 opcode, s32 param) {
  unsigned long addr, val;
  s32 preDeref = param, postDeref = 0;

  if (opcode & UNWIND_OPCODEF_DEREF) {
    // For expressions that dereference the base expression, the parameter is constructed
    // of pre-dereference and post-derefence operands. Unpack those.
    preDeref &= ~UNWIND_DEREF_MASK;
    postDeref = (param & UNWIND_DEREF_MASK) * UNWIND_DEREF_MULTIPLIER;
  }

  // Resolve the 'BASE' register, and fetch the CFA/FP/SP value.
  switch (opcode & ~UNWIND_OPCODEF_DEREF) {
  case UNWIND_OPCODE_BASE_CFA:
    addr = cfa;
    break;
  case UNWIND_OPCODE_BASE_FP:
    addr = state->fp;
    break;
  case UNWIND_OPCODE_BASE_SP:
    addr = state->sp;
    break;
#if defined(__aarch64__)
  case UNWIND_OPCODE_BASE_LR:
    DEBUG_PRINT("unwind: lr");

    if (state->lr == 0) {
        increment_metric(metricID_UnwindNativeLr0);
        DEBUG_PRINT("Failure to unwind frame: zero LR at %llx", state->pc);
        return 0;
    }

    return state->lr;
#endif
#if defined(__x86_64__)
  case UNWIND_OPCODE_BASE_REG:
    val = (param & ~UNWIND_REG_MASK) >> 1;
    DEBUG_PRINT("unwind: r%d+%lu", param & UNWIND_REG_MASK, val);
    switch (param & UNWIND_REG_MASK) {
    case 0: // rax
      addr = state->rax;
      break;
    case 9: // r9
      addr = state->r9;
      break;
    case 11: // r11
      addr = state->r11;
      break;
    case 15: // r15
      addr = state->r15;
      break;
    default:
      return 0;
    }
    return addr + val;
#endif
  default:
    return 0;
  }

#ifdef OPTI_DEBUG
  switch (opcode) {
  case UNWIND_OPCODE_BASE_CFA:
    DEBUG_PRINT("unwind: cfa+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_FP:
    DEBUG_PRINT("unwind: fp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_SP:
    DEBUG_PRINT("unwind: sp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_CFA | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(cfa+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_FP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(fp+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_SP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(sp+%d)+%d", preDeref, postDeref);
    break;
  }
#endif

  // Adjust based on parameter / preDereference adder.
  addr += preDeref;
  if ((opcode & UNWIND_OPCODEF_DEREF) == 0) {
    // All done: return "BASE + param"
    return addr;
  }

  // Dereference, and add the postDereference adder.
  if (bpf_probe_read_user(&val, sizeof(val), (void*) addr)) {
    DEBUG_PRINT("unwind failed to dereference address 0x%lx", addr);
    return 0;
  }
  // Return: "*(BASE + preDeref) + postDeref"
  return val + postDeref;
}

// Stack unwinding in the absence of frame pointers can be a bit involved, so
// this comment explains what the following code does.
//
// One begins unwinding a frame somewhere in the middle of execution.
// On x86_64, registers RIP (PC), RSP (SP), and RBP (FP) are available.
//
// This function resolves a "stack delta" command from from our internal maps.
// This stack delta refers to a rule on how to unwind the state. In the simple
// case it just provides SP delta and potentially offset from where to recover
// FP value. See unwind_register_address() on the expressions supported.
//
// The function sets the bool pointed to by the given `stop` pointer to `false`
// if the main ebpf unwinder should exit. This is the case if the current PC
// is marked with UNWIND_COMMAND_STOP which marks entry points (main function,
// thread spawn function, signal handlers, ...).
#if defined(__x86_64__)
static ErrorCode unwind_one_frame(u64 pid, u32 frame_idx, UnwindState *state, bool* stop) {
  *stop = false;

  u32 unwindInfo = 0;
  u64 rt_regs[18];
  int addrDiff = 0;
  u64 cfa = 0;

  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
  if (error) {
    return error;
  }

  if (unwindInfo & STACK_DELTA_COMMAND_FLAG) {
    switch (unwindInfo & ~STACK_DELTA_COMMAND_FLAG) {
    case UNWIND_COMMAND_PLT:
      // The toolchains routinely emit a fixed DWARF expression to unwind the full
      // PLT table with one expression to reduce .eh_frame size.
      // This is the hard coded implementation of this expression. For further details,
      // see https://hal.inria.fr/hal-02297690/document, page 4. (DOI: 10.1145/3360572)
      cfa = state->sp + 8 + ((((state->pc & 15) >= 11) ? 1 : 0) << 3);
      DEBUG_PRINT("PLT, cfa=0x%lx", (unsigned long)cfa);
      break;
    case UNWIND_COMMAND_SIGNAL:
      // The rt_sigframe is defined at:
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/sigframe.h?h=v6.4#n59
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/sigcontext.h?h=v6.4#n238
      // offsetof(struct rt_sigframe, uc.uc_mcontext) = 40
      if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void*)(state->sp + 40))) {
        goto err_native_pc_read;
      }
      state->rax = rt_regs[13];
      state->r9 = rt_regs[1];
      state->r11 = rt_regs[3];
      state->r13 = rt_regs[5];
      state->r15 = rt_regs[7];
      state->fp = rt_regs[10];
      state->sp = rt_regs[15];
      state->pc = rt_regs[16];
      state->return_address = false;
      DEBUG_PRINT("signal frame");
      goto frame_ok;
    case UNWIND_COMMAND_STOP:
      *stop = true;
      return ERR_OK;
    default:
      return ERR_UNREACHABLE;
    }
  } else {
    UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &unwindInfo);
    if (!info) {
      increment_metric(metricID_UnwindNativeErrBadUnwindInfoIndex);
      return ERR_NATIVE_BAD_UNWIND_INFO_INDEX;
    }

    s32 param = info->param;
    if (info->mergeOpcode) {
      DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
      if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
        param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
        DEBUG_PRINT("Merged delta match: cfaDelta=%d", unwindInfo);
      }
    }

    // Resolve the frame's CFA (previous PC is fixed to CFA) address, and
    // the previous FP address if any.
    cfa = unwind_register_address(state, 0, info->opcode, param);
    u64 fpa = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);

    if (fpa) {
      bpf_probe_read_user(&state->fp, sizeof(state->fp), (void*)fpa);
    } else if (info->opcode == UNWIND_OPCODE_BASE_FP) {
      // FP used for recovery, but no new FP value received, clear FP
      state->fp = 0;
    }
  }

  if (!cfa || bpf_probe_read_user(&state->pc, sizeof(state->pc), (void*)(cfa - 8))) {
  err_native_pc_read:
    increment_metric(metricID_UnwindNativeErrPCRead);
    return ERR_NATIVE_PC_READ;
  }
  state->sp = cfa;
  unwinder_mark_nonleaf_frame(state);
frame_ok:
  increment_metric(metricID_UnwindNativeFrames);
  return ERR_OK;
}
#elif defined(__aarch64__)
static ErrorCode unwind_one_frame(u64 pid, u32 frame_idx, struct UnwindState *state, bool* stop) {
  *stop = false;

  u32 unwindInfo = 0;
  int addrDiff = 0;
  u64 rt_regs[34];
  u64 cfa = 0;

  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
  if (error) {
    return error;
  }

  if (unwindInfo & STACK_DELTA_COMMAND_FLAG) {
    switch (unwindInfo & ~STACK_DELTA_COMMAND_FLAG) {
    case UNWIND_COMMAND_SIGNAL:
      // On aarch64 the struct rt_sigframe is at:
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/signal.c?h=v6.4#n39
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/include/uapi/asm/sigcontext.h?h=v6.4#n28
      // offsetof(struct rt_sigframe, uc.uc_mcontext.regs[0]) = 312
      //   offsetof(struct rt_sigframe, uc)       128 +
      //   offsetof(struct ucontext, uc_mcontext) 176 +
      //   offsetof(struct sigcontext, regs[0])   8
      if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void*)(state->sp + 312))) {
        goto err_native_pc_read;
      }
      state->pc = normalize_pac_ptr(rt_regs[32]);
      state->sp = rt_regs[31];
      state->fp = rt_regs[29];
      state->lr = normalize_pac_ptr(rt_regs[30]);
      state->r22 = rt_regs[22];
      state->return_address = false;
      state->lr_invalid = false;
      DEBUG_PRINT("signal frame");
      goto frame_ok;
    case UNWIND_COMMAND_STOP:
      *stop = true;
      return ERR_OK;
    default:
      return ERR_UNREACHABLE;
    }
  }

  UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &unwindInfo);
  if (!info) {
    increment_metric(metricID_UnwindNativeErrBadUnwindInfoIndex);
    DEBUG_PRINT("Giving up due to invalid unwind info array index");
    return ERR_NATIVE_BAD_UNWIND_INFO_INDEX;
  }

  s32 param = info->param;
  if (info->mergeOpcode) {
    DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
    if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
      param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
      DEBUG_PRINT("Merged delta match: cfaDelta=%d", unwindInfo);
    }
  }

  // Resolve the frame CFA (previous PC is fixed to CFA) address
  cfa = unwind_register_address(state, 0, info->opcode, param);

  // Resolve Return Address, it is either the value of link register or
  // stack address where RA is stored
  u64 ra = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);
  if (ra) {
    if (info->fpOpcode == UNWIND_OPCODE_BASE_LR) {
      // Allow LR unwinding only if it's known to be valid: either because
      // it's the topmost user-mode frame, or recovered by signal trampoline.
      if (state->lr_invalid) {
        increment_metric(metricID_UnwindNativeErrLrUnwindingMidTrace);
        return ERR_NATIVE_LR_UNWINDING_MID_TRACE;
      }

      // set return address location to link register
      state->pc = ra;
    } else {
      DEBUG_PRINT("RA: %016llX", (u64)ra);

      // read the value of RA from stack
      if (bpf_probe_read_user(&state->pc, sizeof(state->pc), (void*)ra)) {
        // error reading memory, mark RA as invalid
        ra = 0;
      }
    }

    state->pc = normalize_pac_ptr(state->pc);
  }

  if (!ra) {
  err_native_pc_read:
    // report failure to resolve RA and stop unwinding
    increment_metric(metricID_UnwindNativeErrPCRead);
    DEBUG_PRINT("Giving up due to failure to resolve RA");
    return ERR_NATIVE_PC_READ;
  }

  // Try to resolve frame pointer
  // simple heuristic for FP based frames
  // the GCC compiler usually generates stack frame records in such a way,
  // so that FP/RA pair is at the bottom of a stack frame (stack frame
  // record at lower addresses is followed by stack vars at higher ones)
  // this implies that if no other changes are applied to the stack such
  // as alloca(), following the prolog SP/FP points to the frame record
  // itself, in such a case FP offset will be equal to 8
  if (info->fpParam == 8) {
    // we can assume the presence of frame pointers
    if (info->fpOpcode != UNWIND_OPCODE_BASE_LR) {
      // FP precedes the RA on the stack (Aarch64 ABI requirement)
      bpf_probe_read_user(&state->fp, sizeof(state->fp), (void*)(ra - 8));
    }
  }

  state->sp = cfa;
  unwinder_mark_nonleaf_frame(state);
frame_ok:
  increment_metric(metricID_UnwindNativeFrames);
  return ERR_OK;
}
#else
  #error unsupported architecture
#endif

// Initialize state from pt_regs
static inline ErrorCode copy_state_regs(UnwindState *state,
                                        struct pt_regs *regs,
                                        bool interrupted_kernelmode)
{
#if defined(__x86_64__)
  // Check if the process is running in 32-bit mode on the x86_64 system.
  // This check follows the Linux kernel implementation of user_64bit_mode() in
  // arch/x86/include/asm/ptrace.h.
  if (regs->cs == __USER32_CS) {
    return ERR_NATIVE_X64_32BIT_COMPAT_MODE;
  }
  state->pc = regs->ip;
  state->sp = regs->sp;
  state->fp = regs->bp;
  state->rax = regs->ax;
  state->r9 = regs->r9;
  state->r11 = regs->r11;
  state->r13 = regs->r13;
  state->r15 = regs->r15;

  // Treat syscalls as return addresses, but not IRQ handling, page faults, etc..
  // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/x86/include/asm/syscall.h#L31-L39
  // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/x86/entry/entry_64.S#L847
  state->return_address = interrupted_kernelmode && regs->orig_ax != -1;
#elif defined(__aarch64__)
  // For backwards compatibility aarch64 can run 32-bit code.
  // Check if the process is running in this 32-bit compat mod.
  if (regs->pstate & PSR_MODE32_BIT) {
    return ERR_NATIVE_AARCH64_32BIT_COMPAT_MODE;
  }
  state->pc = normalize_pac_ptr(regs->pc);
  state->sp = regs->sp;
  state->fp = regs->regs[29];
  state->lr = normalize_pac_ptr(regs->regs[30]);
  state->r22 = regs->regs[22];

  // Treat syscalls as return addresses, but not IRQ handling, page faults, etc..
  // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/arm64/include/asm/ptrace.h#L118
  // https://github.com/torvalds/linux/blob/2ef5971ff3/arch/arm64/include/asm/ptrace.h#L206-L209
  //
  // Note: We do not use `unwinder_mark_nonleaf_frame` here,
  // because the frame is a leaf frame from the perspective of the user stack,
  // regardless of whether we are in a syscall.
  state->return_address = interrupted_kernelmode && regs->syscallno != -1;
  state->lr_invalid = false;
#endif

  return ERR_OK;
}

#ifndef TESTING_COREDUMP

// Read the task's entry stack pt_regs. This has identical functionality
// to bpf_task_pt_regs which is emulated to support older kernels.
// Once kernel requirement is increased to 5.15 this can be replaced with
// the bpf_task_pt_regs() helper.
static inline
long get_task_pt_regs(struct task_struct *task, SystemConfig* syscfg) {
  u64 stack_ptr = (u64)task + syscfg->task_stack_offset;
  long stack_base;
  if (bpf_probe_read_kernel(&stack_base, sizeof(stack_base), (void*) stack_ptr)) {
    return 0;
  }
  return stack_base + syscfg->stack_ptregs_offset;
}

// Determine whether the given pt_regs are from user-mode register context.
// This needs to detect also invalid pt_regs in case we its kernel thread stack
// without valid user mode pt_regs so is_kernel_address(pc) is not enough.
static inline
bool ptregs_is_usermode(struct pt_regs *regs) {
#if defined(__x86_64__)
  // On x86_64 the user mode SS should always be __USER_DS.
  if (regs->ss != __USER_DS) {
    return false;
  }
  return true;
#elif defined(__aarch64__)
  // Check if the processor state is in the EL0t what linux uses for usermode.
  if ((regs->pstate & PSR_MODE_MASK) != PSR_MODE_EL0t) {
    return false;
  }
  return true;
#else
#error add support for new architecture
#endif
}

// Extract the usermode pt_regs for current task. Use context given pt_regs
// if it is usermode regs, or resolve it via struct task_struct.
//
// State registers are not touched (get_pristine_per_cpu_record already reset it)
// if something fails. has_usermode_regs is set to true if a user-mode register
// context was found: not every thread that we interrupt will actually have
// a user-mode context (e.g. kernel worker threads won't).
static inline ErrorCode get_usermode_regs(struct pt_regs *ctx,
                                          UnwindState *state,
                                          bool *has_usermode_regs) {
  ErrorCode error;

  if (!ptregs_is_usermode(ctx)) {
    u32 key = 0;
    SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
    if (!syscfg) {
      // Unreachable: array maps are always fully initialized.
      return ERR_UNREACHABLE;
    }

    // Use the current task's entry pt_regs
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    long ptregs_addr = get_task_pt_regs(task, syscfg);

    struct pt_regs regs;
    if (!ptregs_addr || bpf_probe_read_kernel(&regs, sizeof(regs), (void*) ptregs_addr)) {
      increment_metric(metricID_UnwindNativeErrReadKernelModeRegs);
      return ERR_NATIVE_READ_KERNELMODE_REGS;
    }

    if (!ptregs_is_usermode(&regs)) {
      // No usermode registers context found.
      return ERR_OK;
    }
    error = copy_state_regs(state, &regs, true);
  } else {
    // User mode code interrupted, registers are available via the ebpf context.
    error = copy_state_regs(state, ctx, false);
  }
  if (error == ERR_OK) {
    DEBUG_PRINT("Read regs: pc: %llx sp: %llx fp: %llx", state->pc, state->sp, state->fp);
    *has_usermode_regs = true;
  }
  return error;
}

#else // TESTING_COREDUMP

static inline ErrorCode get_usermode_regs(struct pt_regs *ctx,
                                          UnwindState *state,
                                          bool *has_usermode_regs) {
  // Coredumps provide always usermode pt_regs directly.
  ErrorCode error = copy_state_regs(state, ctx, false);
  if (error == ERR_OK) {
    *has_usermode_regs = true;
  }
  return error;
}

#endif

SEC("perf_event/unwind_native")
int unwind_native(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  int unwinder;
  ErrorCode error;
#pragma unroll
  for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;

    // Unwind native code
    u32 frame_idx = trace->stack_len;
    DEBUG_PRINT("==== unwind_native %d ====", frame_idx);
    increment_metric(metricID_UnwindNativeAttempts);

    // Push frame first. The PC is valid because a text section mapping was found.
    DEBUG_PRINT("Pushing %llx %llx to position %u on stack",
                record->state.text_section_id, record->state.text_section_offset,
                trace->stack_len);
    error = push_native(trace, record->state.text_section_id, record->state.text_section_offset,
        record->state.return_address);
    if (error) {
      DEBUG_PRINT("failed to push native frame");
      break;
    }

    // Unwind the native frame using stack deltas. Stop if no next frame.
    bool stop;
    error = unwind_one_frame(trace->pid, frame_idx, &record->state, &stop);
    if (error || stop) {
      break;
    }

    // Continue unwinding
    DEBUG_PRINT(" pc: %llx sp: %llx fp: %llx", record->state.pc, record->state.sp, record->state.fp);
    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_NATIVE) {
      break;
    }
  }

  // Tail call needed for recursion, switching to interpreter unwinder, or reporting
  // trace due to end-of-trace or error. The unwinder program index is set accordingly.
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in unwind_native", unwinder);
  return -1;
}

static inline
int collect_trace(struct pt_regs *ctx) {
  // Get the PID and TGID register.
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;
  u32 tid = id & 0xFFFFFFFF;

  if (pid == 0) {
    return 0;
  }

  u64 ktime = bpf_ktime_get_ns();

  DEBUG_PRINT("==== do_perf_event ====");

  // The trace is reused on each call to this function so we have to reset the
  // variables used to maintain state.
  DEBUG_PRINT("Resetting CPU record");
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace = &record->trace;
  trace->pid = pid;
  trace->tid = tid;
  trace->ktime = ktime;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  // Get the kernel mode stack trace first
  trace->kernel_stack_id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_REUSE_STACKID);
  DEBUG_PRINT("kernel stack id = %d", trace->kernel_stack_id);

  // Recursive unwind frames
  int unwinder = PROG_UNWIND_STOP;
  bool has_usermode_regs = false;
  ErrorCode error = get_usermode_regs(ctx, &record->state, &has_usermode_regs);
  if (error || !has_usermode_regs) {
    goto exit;
  }

  if (!pid_information_exists(ctx, pid)) {
    if (report_pid(ctx, pid, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }
  error = get_next_unwinder_after_native_frame(record, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in native_tracer_entry", unwinder);
  return -1;
}

SEC("perf_event/native_tracer_entry")
int native_tracer_entry(struct bpf_perf_event_data *ctx) {
  return collect_trace((struct pt_regs*) &ctx->regs);
}
