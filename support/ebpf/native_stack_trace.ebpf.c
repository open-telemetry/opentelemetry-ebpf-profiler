#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "go_runtime.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// with_debug_output is set during load time.
BPF_RODATA_VAR(u32, with_debug_output, 0)

// filter_idle_frames is set during load time.
BPF_RODATA_VAR(bool, filter_idle_frames, false)

// inverse_pac_mask is set during load time.
BPF_RODATA_VAR(u64, inverse_pac_mask, 0)

// tpbase_offset is set during load time.
// The offset of the Thread Pointer Base variable in `task_struct`. It is
// populated by the host agent based on kernel code analysis.
BPF_RODATA_VAR(u64, tpbase_offset, 0)

// task_stack_offset is set during load time.
// The offset of stack base within `task_struct`.
BPF_RODATA_VAR(u32, task_stack_offset, 0)

// stack_ptregs_offset is set during load time.
// The offset of struct pt_regs within the kernel entry stack.
BPF_RODATA_VAR(u32, stack_ptregs_offset, 0)

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given
// fileID.
#define STACK_DELTA_BUCKET(X)                                                                      \
  struct exe_id_to_##X##_stack_deltas_t {                                                          \
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                                                       \
    __type(key, u64);                                                                              \
    __type(value, u32);                                                                            \
    __uint(max_entries, 4096);                                                                     \
    __array(                                                                                       \
      values, struct {                                                                             \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                          \
        __uint(max_entries, 1 << X);                                                               \
        __type(key, u32);                                                                          \
        __type(value, StackDelta);                                                                 \
      });                                                                                          \
  } exe_id_to_##X##_stack_deltas SEC(".maps");

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
struct unwind_info_array_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, UnwindInfo);
  __uint(max_entries, UNWIND_INFO_MAX_ENTRIES);
} unwind_info_array SEC(".maps");

// The number of native frames to unwind per frame-unwinding eBPF program.
#define NATIVE_FRAMES_PER_PROGRAM 5

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
struct interpreter_offsets_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, OffsetRange);
  __uint(max_entries, 32);
} interpreter_offsets SEC(".maps");

// Maps fileID and page to information of stack deltas associated with that page.
struct stack_delta_page_to_info_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, StackDeltaPageKey);
  __type(value, StackDeltaPageInfo);
  __uint(max_entries, 40000);
} stack_delta_page_to_info SEC(".maps");

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
static EBPF_INLINE ErrorCode unwind_one_frame(UnwindState *state, bool *stop)
{
  *stop = false;

  u32 unwindInfo = 0;
  u64 rt_regs[18];
  int addrDiff = 0;
  u64 cfa      = 0;

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
      if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void *)(state->sp + 40))) {
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
    case UNWIND_COMMAND_STOP: *stop = true; return ERR_OK;
    case UNWIND_COMMAND_FRAME_POINTER:
      if (!unwinder_unwind_frame_pointer(state)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    case UNWIND_COMMAND_GOSTACK: {
      // Cross the Go stack-switch boundary: recover the goroutine's saved context
      // from g.sched (set by runtime.systemstack or runtime.mcall when they
      // switched from the goroutine stack to the g0 system stack).
      //
      // gosave_systemstack_switch (asm_amd64.s) builds gobuf as follows:
      //
      //   MOVQ $runtime.systemstack_switch+8(SB), R9
      //   MOVQ R9, gobuf_pc(R14)        // gobuf.pc = UNDEF marker - useless for unwinding
      //
      //   LEAQ 8(SP), R9
      //   MOVQ R9, gobuf_sp(R14)        // gobuf.sp = SP+8
      //
      //   MOVQ BP, gobuf_bp(R14)        // gobuf.bp = BP of systemstack's caller
      //
      // Stack layout inside gosave_systemstack_switch at the time of LEAQ:
      //   [SP+0] = RA back into systemstack   (pushed by CALL gosave, useless)
      //   [SP+8] = RA caller of systemstack   (pushed by CALL systemstack)
      //
      // systemstack has no PUSH RBP prologue and gosave_systemstack_switch is
      // NOFRAME, so BP is unchanged and holds the frame pointer of systemstack's
      // caller.
      //
      // We want to resume unwinding at the caller of systemstack, so:
      //   pc = *(gobuf.sp)   = RA caller of systemstack
      //   sp = gobuf.sp + 8  = beyond the consumed RA slot (equivalent of RET's SP+=8)
      //   fp = gobuf.bp      = frame pointer of the caller
      //
      // gobuf.pc (systemstack_switch+8 = UNDEF) is intentionally ignored: it is a
      // synthetic marker for Go's stack scanner and scheduler, not a real return address.
      //
      // https://github.com/golang/go/blob/917949cc1d16c652cb09ba369718f45e5d814d8f/src/runtime/asm_amd64.s#L886
      PerCPURecord *cpu_record = get_per_cpu_record();
      if (!cpu_record) {
        DEBUG_PRINT("GOSTACK: no per-CPU record, stopping");
        *stop = true;
        return ERR_OK;
      }
      u32 pid                  = cpu_record->trace.pid;
      GoLabelsOffsets *go_offs = bpf_map_lookup_elem(&go_labels_procs, &pid);
      if (!go_offs) {
        DEBUG_PRINT("GOSTACK: no Go offsets for this process, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!go_offs->sched_sp) {
        DEBUG_PRINT("GOSTACK: sched offsets not configured, stopping");
        *stop = true;
        return ERR_OK;
      }
      void *m_ptr = get_m_ptr(go_offs, state);
      if (!m_ptr) {
        DEBUG_PRINT("GOSTACK: failed to get m_ptr, stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 curg = 0;
      if (bpf_probe_read_user(&curg, sizeof(curg), (void *)((u64)m_ptr + go_offs->curg))) {
        DEBUG_PRINT("GOSTACK: failed to read curg, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!curg) {
        DEBUG_PRINT("GOSTACK: no user goroutine (curg == NULL), stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 sched_sp = 0, sched_bp = 0;
      if (bpf_probe_read_user(&sched_sp, sizeof(sched_sp), (void *)(curg + go_offs->sched_sp))) {
        DEBUG_PRINT("GOSTACK: failed to read sched_sp, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!sched_sp) {
        DEBUG_PRINT("GOSTACK: gobuf not populated (sched_sp==0), stopping");
        *stop = true;
        return ERR_OK;
      }
      if (bpf_probe_read_user(&sched_bp, sizeof(sched_bp), (void *)(curg + go_offs->sched_bp))) {
        DEBUG_PRINT("GOSTACK: failed to read sched_bp, stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 caller_pc = 0;
      if (bpf_probe_read_user(&caller_pc, sizeof(caller_pc), (void *)sched_sp)) {
        DEBUG_PRINT("GOSTACK: failed to read caller PC from goroutine stack, stopping");
        *stop = true;
        return ERR_OK;
      }
      DEBUG_PRINT(
        "GOSTACK: recovered caller context: pc=0x%lx, sp=0x%lx, fp=0x%lx",
        (unsigned long)caller_pc,
        (unsigned long)(sched_sp + 8),
        (unsigned long)sched_bp);
      state->pc = caller_pc;
      state->sp = sched_sp + 8;
      state->fp = sched_bp;
      unwinder_mark_nonleaf_frame(state);
      goto frame_ok;
    }
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
static EBPF_INLINE ErrorCode unwind_one_frame(struct UnwindState *state, bool *stop)
{
  *stop = false;

  u32 unwindInfo = 0;
  int addrDiff   = 0;
  u64 rt_regs[34];

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
      if (bpf_probe_read_user(&rt_regs, sizeof(rt_regs), (void *)(state->sp + 312))) {
        goto err_native_pc_read;
      }
      state->pc  = normalize_pac_ptr(rt_regs[32]);
      state->sp  = rt_regs[31];
      state->fp  = rt_regs[29];
      state->lr  = normalize_pac_ptr(rt_regs[30]);
      state->r20 = rt_regs[20];
      state->r22 = rt_regs[22];
      state->r28 = rt_regs[28];

      state->return_address = false;
      state->lr_invalid     = false;
      DEBUG_PRINT("signal frame");
      goto frame_ok;
    case UNWIND_COMMAND_STOP: *stop = true; return ERR_OK;
    case UNWIND_COMMAND_FRAME_POINTER:
      if (!unwinder_unwind_frame_pointer(state)) {
        goto err_native_pc_read;
      }
      goto frame_ok;
    case UNWIND_COMMAND_GOSTACK: {
      // Cross the Go stack-switch boundary: recover the goroutine's saved context
      // from g.sched (set by runtime.systemstack or runtime.mcall when they
      // switched from the goroutine stack to the g0 system stack).
      //
      // gosave_systemstack_switch (asm_arm64.s) builds gobuf as follows:
      //
      //   MOVD	$runtime.systemstack_switch(SB), R0
      //   ADD	$8, R0 // get past prologue
      //   MOVD	R0, (g_sched+gobuf_pc)(g)         // gobuf.pc = UNDEF marker - useless for unwinding
      //
      //   MOVD	RSP, R0
      //   MOVD	R0, (g_sched+gobuf_sp)(g)         // gobuf.sp = RSP
      //
      //   MOVD	R29, (g_sched+gobuf_bp)(g)        // gobuf.bp = FP of systemstack's caller
      //
      //   MOVD	$0, (g_sched+gobuf_lr)(g)         // gobuf.lr = 0 (explicitly zeroed, never usable)
      //
      // systemstack on arm64 has a frame pointer prologue:
      //   STP (FP, LR), -16(SP)!        // SP -= 16, [SP+0] = caller FP, [SP+8] = LR (RA caller)
      //
      // Stack layout inside gosave_systemstack_switch at the time of MOVD RSP:
      //   [SP+0]  = saved FP of systemstack's caller   (pushed by STP, useless)
      //   [SP+8]  = LR = RA caller of systemstack      (pushed by STP)
      //
      // We want to resume unwinding at the caller of systemstack, so:
      //   pc = *(gobuf.sp + 8)   = LR saved by STP = RA caller of systemstack
      //   sp = gobuf.sp + 16     = beyond the consumed FP+LR slot (STP allocated 16 bytes)
      //   fp = gobuf.bp          = frame pointer of the caller
      //
      // gobuf.pc (systemstack_switch = UNDEF) is intentionally ignored: it is a
      // synthetic marker for Go's stack scanner and scheduler, not a real return address.
      //
      // https://github.com/golang/go/blob/5a928e5a37dc632bbb1794fe0e0846e6352be8b2/src/runtime/asm_arm64.s#L1124
      PerCPURecord *cpu_record = get_per_cpu_record();
      if (!cpu_record) {
        DEBUG_PRINT("GOSTACK: no per-CPU record, stopping");
        *stop = true;
        return ERR_OK;
      }
      u32 pid                  = cpu_record->trace.pid;
      GoLabelsOffsets *go_offs = bpf_map_lookup_elem(&go_labels_procs, &pid);
      if (!go_offs) {
        DEBUG_PRINT("GOSTACK: no Go offsets for this process, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!go_offs->sched_sp) {
        DEBUG_PRINT("GOSTACK: sched offsets not configured, stopping");
        *stop = true;
        return ERR_OK;
      }
      void *m_ptr = get_m_ptr(go_offs, state);
      if (!m_ptr) {
        DEBUG_PRINT("GOSTACK: failed to get m_ptr, stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 curg = 0;
      if (bpf_probe_read_user(&curg, sizeof(curg), (void *)((u64)m_ptr + go_offs->curg))) {
        DEBUG_PRINT("GOSTACK: failed to read curg, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!curg) {
        DEBUG_PRINT("GOSTACK: no user goroutine (curg == NULL), stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 sched_sp = 0, sched_bp = 0;
      if (bpf_probe_read_user(&sched_sp, sizeof(sched_sp), (void *)(curg + go_offs->sched_sp))) {
        DEBUG_PRINT("GOSTACK: failed to read sched_sp, stopping");
        *stop = true;
        return ERR_OK;
      }
      if (!sched_sp) {
        DEBUG_PRINT("GOSTACK: gobuf not populated (sched_sp==0), stopping");
        *stop = true;
        return ERR_OK;
      }
      if (bpf_probe_read_user(&sched_bp, sizeof(sched_bp), (void *)(curg + go_offs->sched_bp))) {
        DEBUG_PRINT("GOSTACK: failed to read sched_bp, stopping");
        *stop = true;
        return ERR_OK;
      }
      u64 caller_pc = 0;
      if (bpf_probe_read_user(&caller_pc, sizeof(caller_pc), (void *)(sched_sp + 8))) {
        DEBUG_PRINT("GOSTACK: failed to read caller PC from goroutine stack, stopping");
        *stop = true;
        return ERR_OK;
      }
      DEBUG_PRINT(
        "GOSTACK: recovered caller context: pc=0x%lx, sp=0x%lx, fp=0x%lx",
        (unsigned long)caller_pc,
        (unsigned long)(sched_sp + 16),
        (unsigned long)sched_bp);
      state->pc  = normalize_pac_ptr(caller_pc);
      state->sp  = sched_sp + 16;
      state->fp  = sched_bp;
      state->lr  = 0;
      // Update r28 (the g register on aarch64) to point to curg so that
      // subsequent get_m_ptr calls use the correct goroutine pointer.
      state->r28 = curg;
      unwinder_mark_nonleaf_frame(state);
      goto frame_ok;
    }
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

// unwind_native is the tail call destination for PROG_UNWIND_NATIVE.
static EBPF_INLINE int unwind_native(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  int unwinder;
  ErrorCode error;
  for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;

    // Unwind native code
    DEBUG_PRINT("==== unwind_native %d ====", trace->num_frames);
    increment_metric(metricID_UnwindNativeAttempts);

    // Push frame first. The PC is valid because a text section mapping was found.
    DEBUG_PRINT(
      "Pushing %llx %llx to position %u on stack",
      record->state.text_section_id,
      record->state.text_section_offset,
      trace->num_frames);
    error = push_native(
      &record->state,
      trace,
      record->state.text_section_id,
      record->state.text_section_offset,
      record->state.return_address);
    if (error) {
      DEBUG_PRINT("failed to push native frame");
      break;
    }

    // Unwind the native frame using stack deltas. Stop if no next frame.
    bool stop;
    error = unwind_one_frame(&record->state, &stop);
    if (error || stop) {
      break;
    }

    // Continue unwinding
    DEBUG_PRINT(
      " pc: %llx sp: %llx fp: %llx", record->state.pc, record->state.sp, record->state.fp);
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

SEC("perf_event/native_tracer_entry")
int native_tracer_entry(struct bpf_perf_event_data *ctx)
{
  // Get the PID and TGID register.
  u64 id  = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;
  u32 tid = id & 0xFFFFFFFF;

  if (pid == 0 && filter_idle_frames) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  return collect_trace((struct pt_regs *)&ctx->regs, TRACE_SAMPLING, pid, tid, ts, 0);
}
MULTI_USE_FUNC(unwind_native)
