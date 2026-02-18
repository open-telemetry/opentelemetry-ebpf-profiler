#ifndef OPTI_NATIVE_STACK_TRACE_H
#define OPTI_NATIVE_STACK_TRACE_H

// Unwind info value for invalid stack delta
#define STACK_DELTA_INVALID (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_INVALID)
#define STACK_DELTA_STOP    (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_STOP)

// The number of native frames to unwind per frame-unwinding eBPF program.
#define NATIVE_FRAMES_PER_PROGRAM 8

// Record a native frame
static EBPF_INLINE ErrorCode
push_native(UnwindState *state, Trace *trace, u64 file, u64 line, bool return_address)
{
  const u8 ra_flag = return_address ? FRAME_FLAG_RETURN_ADDRESS : 0;

  u64 *data = push_frame(state, trace, FRAME_MARKER_NATIVE, ra_flag, line, 1);
  if (!data) {
    return ERR_STACK_LENGTH_EXCEEDED;
  }
  data[0] = file;
  return ERR_OK;
}

// A single step for the bsearch into the big_stack_deltas array. This is really a textbook bsearch
// step, built in a way to update the value of *lo and *hi. This function will be called repeatedly
// (since we cannot do loops). The return value signals whether the bsearch came to an end / found
// the right element or whether it needs to continue.
static EBPF_INLINE bool bsearch_step(void *inner_map, u32 *lo, u32 *hi, u16 page_offset)
{
  u32 pivot         = (*lo + *hi) >> 1;
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
static EBPF_INLINE void *get_stack_delta_map(int mapID)
{
  switch (mapID) {
  case 8: return &exe_id_to_8_stack_deltas;
  case 9: return &exe_id_to_9_stack_deltas;
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
static EBPF_INLINE ErrorCode get_stack_delta(UnwindState *state, int *addrDiff, u32 *unwindInfo)
{
  u64 exe_id = state->text_section_id;

  // Look up the stack delta page information for this address.
  StackDeltaPageKey key = {};
  key.fileID            = state->text_section_id;
  key.page              = state->text_section_offset & ~STACK_DELTA_PAGE_MASK;
  DEBUG_PRINT(
    "Look up stack delta for %lx:%lx",
    (unsigned long)state->text_section_id,
    (unsigned long)state->text_section_offset);
  StackDeltaPageInfo *info = bpf_map_lookup_elem(&stack_delta_page_to_info, &key);
  if (!info) {
    DEBUG_PRINT(
      "Failure to look up stack delta page fileID %lx, page %lx",
      (unsigned long)key.fileID,
      (unsigned long)key.page);
    state->error_metric = metricID_UnwindNativeErrLookupTextSection;
    return ERR_NATIVE_LOOKUP_TEXT_SECTION;
  }

  void *outer_map = get_stack_delta_map(info->mapID);
  if (!outer_map) {
    DEBUG_PRINT(
      "Failure to look up outer map for text section %lx in mapID %d",
      (unsigned long)exe_id,
      (int)info->mapID);
    state->error_metric = metricID_UnwindNativeErrLookupStackDeltaOuterMap;
    return ERR_NATIVE_LOOKUP_STACK_DELTA_OUTER_MAP;
  }

  void *inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
  if (!inner_map) {
    DEBUG_PRINT("Failure to look up inner map for text section %lx", (unsigned long)exe_id);
    state->error_metric = metricID_UnwindNativeErrLookupStackDeltaInnerMap;
    return ERR_NATIVE_LOOKUP_STACK_DELTA_INNER_MAP;
  }

  // Preinitialize the idx for the index to use for page without any deltas.
  u32 idx         = info->firstDelta;
  u16 page_offset = state->text_section_offset & STACK_DELTA_PAGE_MASK;
  if (info->numDeltas) {
    // Page has deltas, so find the correct one to use using binary search.
    u32 lo = info->firstDelta;
    u32 hi = lo + info->numDeltas;

    DEBUG_PRINT(
      "Intervals should be from %lu to %lu (mapID %d)",
      (unsigned long)lo,
      (unsigned long)hi,
      (int)info->mapID);

    // Do the binary search, up to 16 iterations. Deltas are paged to 64kB pages.
    // They can contain at most 64kB deltas even if everything is single byte opcodes.
    int i;
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

  DEBUG_PRINT(
    "delta index %d, addrLow 0x%x, unwindInfo %d", idx, delta->addrLow, delta->unwindInfo);

  // Calculate PC delta from stack delta for merged delta comparison
  int deltaOffset = (int)page_offset - (int)delta->addrLow;
  if (idx < info->firstDelta) {
    // PC is below the first delta of the corresponding page. This means that
    // delta->addrLow contains address relative to one page before the page_offset.
    // Fix up the deltaOffset with this difference of base pages.
    deltaOffset += 1 << STACK_DELTA_PAGE_BITS;
  }

  *addrDiff   = deltaOffset;
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

// unwind_calc_register calculates the given basic register expression of
// format "BASE_REG + param".
static EBPF_INLINE u64 unwind_calc_register(UnwindState *state, u8 baseReg, s32 param)
{
  return state->regs[baseReg % (sizeof(state->regs) / sizeof(state->regs[0]))] + param;
}

#if defined(__x86_64__)

// unwind_calc_register_with_deref calculates the expression as:
// - basic expression "BASE_REG + param"
// - expression with a dereference "*(BASE_REG + preDeref) + postDeref"
static EBPF_INLINE u64
unwind_calc_register_with_deref(UnwindState *state, u8 baseReg, s32 param, bool deref)
{
  s32 preDeref = param, postDeref = 0;

  if (deref) {
    // For expressions that dereference the base expression, the parameter is constructed
    // of pre-dereference and post-derefence operands. Unpack those.
    preDeref &= ~UNWIND_DEREF_MASK;
    postDeref = (param & UNWIND_DEREF_MASK) * UNWIND_DEREF_MULTIPLIER;
  }

  // Resolve the "BASE + param" before potential derereference
  u64 addr = unwind_calc_register(state, baseReg, preDeref);
  if (!deref) {
    // All done: return "BASE + param"
    return addr;
  }

  // Dereference, and add the postDereference adder.
  unsigned long val;
  if (bpf_probe_read_user(&val, sizeof(val), (void *)addr)) {
    DEBUG_PRINT("unwind failed to dereference address 0x%lx", (unsigned long)addr);
    return 0;
  }
  // Return: "*(BASE + preDeref) + postDeref"
  return val + postDeref;
}
#endif

// Stack unwinding in the absence of frame pointers can be a bit involved, so
// this comment explains what the following code does.
//
// One begins unwinding a frame somewhere in the middle of execution.
// On x86_64, registers RIP (PC), RSP (SP), and RBP (FP) are available.
//
// This function resolves a "stack delta" command from from our internal maps.
// This stack delta refers to a rule on how to unwind the state. In the simple
// case it just provides SP delta and potentially offset from where to recover
// FP value. See unwind_calc_register[_with_deref]() on the expressions supported.
//
// The function sets the bool pointed to by the given `stop` pointer to `false`
// if the main ebpf unwinder should exit. This is the case if the current PC
// is marked with UNWIND_COMMAND_STOP which marks entry points (main function,
// thread spawn function, signal handlers, ...).
#if defined(__x86_64__)
static EBPF_INLINE ErrorCode unwind_one_frame(PerCPURecord *record, bool *stop)
{
  UnwindState *state = &record->state;
  *stop              = false;

  u32 unwindInfo = 0;
  int addrDiff   = 0;
  u64 cfa        = 0;

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
    case UNWIND_COMMAND_SIGNAL: {
      // Use the PerCPURecord scratch union instead of a stack-local buffer to avoid
      // exceeding the 512-byte BPF stack limit when inlined into interpreters.
      u64 *rt_regs = record->rt_regs;
      // The rt_sigframe is defined at:
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/sigframe.h?h=v6.4#n59
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/sigcontext.h?h=v6.4#n238
      // offsetof(struct rt_sigframe, uc.uc_mcontext) = 40
      if (bpf_probe_read_user(rt_regs, 18 * sizeof(u64), (void *)(state->sp + 40))) {
        goto err_native_pc_read;
      }
      state->rax = rt_regs[13];
      state->r9  = rt_regs[1];
      state->r11 = rt_regs[3];
      state->r13 = rt_regs[5];
      state->r15 = rt_regs[7];
      state->fp  = rt_regs[10];
      state->sp  = rt_regs[15];
      state->pc  = rt_regs[16];

      state->return_address = false;
      DEBUG_PRINT("signal frame");
      goto frame_ok;
    }
    case UNWIND_COMMAND_STOP: *stop = true; return ERR_OK;
    case UNWIND_COMMAND_FRAME_POINTER:
      if (!unwinder_unwind_frame_pointer(state)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    case UNWIND_COMMAND_GO_MORESTACK:
      if (!unwinder_unwind_go_morestack(record)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    default: return ERR_UNREACHABLE;
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
    state->cfa = cfa = unwind_calc_register_with_deref(
      state, info->baseReg, param, (info->flags & UNWIND_FLAG_DEREF_CFA) != 0);
    u64 fpa = unwind_calc_register(state, info->auxBaseReg, info->auxParam);

    if (fpa) {
      bpf_probe_read_user(&state->fp, sizeof(state->fp), (void *)fpa);
    } else if (info->baseReg == UNWIND_REG_FP) {
      // FP used for recovery, but no new FP value received, clear FP
      state->fp = 0;
    }
  }

  if (!cfa || bpf_probe_read_user(&state->pc, sizeof(state->pc), (void *)(cfa - 8))) {
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
static EBPF_INLINE ErrorCode unwind_one_frame(struct PerCPURecord *record, bool *stop)
{
  UnwindState *state = &record->state;
  *stop              = false;

  u32 unwindInfo = 0;
  int addrDiff   = 0;

  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
  if (error) {
    return error;
  }

  if (unwindInfo & STACK_DELTA_COMMAND_FLAG) {
    switch (unwindInfo & ~STACK_DELTA_COMMAND_FLAG) {
    case UNWIND_COMMAND_SIGNAL: {
      // Use the PerCPURecord scratch union instead of a stack-local buffer to avoid
      // exceeding the 512-byte BPF stack limit when inlined into interpreters.
      u64 *rt_regs = record->rt_regs;
      // On aarch64 the struct rt_sigframe is at:
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/signal.c?h=v6.4#n39
      // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/include/uapi/asm/sigcontext.h?h=v6.4#n28
      // offsetof(struct rt_sigframe, uc.uc_mcontext.regs[0]) = 312
      //   offsetof(struct rt_sigframe, uc)       128 +
      //   offsetof(struct ucontext, uc_mcontext) 176 +
      //   offsetof(struct sigcontext, regs[0])   8
      if (bpf_probe_read_user(rt_regs, 34 * sizeof(u64), (void *)(state->sp + 312))) {
        goto err_native_pc_read;
      }
      state->pc  = normalize_pac_ptr(rt_regs[32]);
      state->sp  = rt_regs[31];
      state->fp  = rt_regs[29];
      state->lr  = normalize_pac_ptr(rt_regs[30]);
      state->r20 = rt_regs[20];
      state->r7  = rt_regs[7];
      state->r22 = rt_regs[22];
      state->r28 = rt_regs[28];

      state->return_address = false;
      state->lr_invalid     = false;
      DEBUG_PRINT("signal frame");
      goto frame_ok;
    }
    case UNWIND_COMMAND_STOP: *stop = true; return ERR_OK;
    case UNWIND_COMMAND_FRAME_POINTER:
      if (!unwinder_unwind_frame_pointer(state)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    case UNWIND_COMMAND_GO_MORESTACK:
      if (!unwinder_unwind_go_morestack(record)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    default: return ERR_UNREACHABLE;
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
  state->cfa = unwind_calc_register(state, info->baseReg, param);

  // Resolve Return Address, it is either the value of link register or
  // stack address where RA is stored
  u64 ra = unwind_calc_register(state, info->auxBaseReg, info->auxParam);
  if (!ra) {
    if (info->auxBaseReg == UNWIND_REG_LR) {
      increment_metric(metricID_UnwindNativeLr0);
    } else {
    err_native_pc_read:
      increment_metric(metricID_UnwindNativeErrPCRead);
    }
    // report failure to resolve RA and stop unwinding
    DEBUG_PRINT("Giving up due to failure to resolve RA");
    return ERR_NATIVE_PC_READ;
  }

  if (info->auxBaseReg == UNWIND_REG_LR) {
    // Allow LR unwinding only if it's known to be valid: either because
    // it's the topmost user-mode frame, or recovered by signal trampoline.
    if (state->lr_invalid) {
      increment_metric(metricID_UnwindNativeErrLrUnwindingMidTrace);
      return ERR_NATIVE_LR_UNWINDING_MID_TRACE;
    }
  } else {
    DEBUG_PRINT("RA: %016llX", (u64)ra);

    // read the value of RA from stack
    int err;
    u64 fpra[2];
    fpra[0] = state->fp;
    if (info->flags & UNWIND_FLAG_FRAME) {
      err = bpf_probe_read_user(fpra, sizeof(fpra), (void *)(ra - 8));
    } else {
      err = bpf_probe_read_user(&fpra[1], sizeof(fpra[0]), (void *)ra);
    }
    if (err) {
      goto err_native_pc_read;
    }
    state->fp = fpra[0];
    ra        = fpra[1];
  }
  state->pc = normalize_pac_ptr(ra);
  state->sp = state->cfa;
  unwinder_mark_nonleaf_frame(state);
frame_ok:
  increment_metric(metricID_UnwindNativeFrames);
  return ERR_OK;
}
#else
  #error unsupported architecture
#endif

#endif
