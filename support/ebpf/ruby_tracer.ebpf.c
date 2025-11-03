// This file contains the code and map definitions for the Ruby tracer

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// Map from Ruby process IDs to a structure containing addresses of variables
// we require in order to build the stack trace
struct ruby_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, RubyProcInfo);
  __uint(max_entries, 1024);
} ruby_procs SEC(".maps");

// The number of Ruby frames to unwind per frame-unwinding eBPF program. If
// we start running out of instructions in the walk_ruby_stack program, one
// option is to adjust this number downwards.
// NOTE the maximum size stack is this times 33
#define FRAMES_PER_WALK_RUBY_STACK 32
// When resolving a CME, we need to traverse environment pointers until we
// find IMEMO_MENT. Since we can't do a while loop, we have to bound this
// the max encountered in experimentation on a production rails app is 6.
// This increases insn for the kernel verifier all code in the ep check "loop"
// is M*N for instruction checks, so be extra sensitive about additions there.
// If we get ERR_RUBY_READ_CME_MAX_EP regularly, we may need to raise it.
#define MAX_EP_CHECKS              6

// Constants related to reading a method entry
// https://github.com/ruby/ruby/blob/523857bfcb0f0cdfd1ed7faa09b9c59a0266e7e2/method.h#L118
#define VM_METHOD_TYPE_ISEQ 0
// https://github.com/ruby/ruby/blob/523857bfcb0f0cdfd1ed7faa09b9c59a0266e7e2/vm_core.h#L1412
#define VM_ENV_FLAG_LOCAL   0x2
// https://github.com/ruby/ruby/blob/523857bfcb0f0cdfd1ed7faa09b9c59a0266e7e2/include/ruby/internal/fl_type.h#L157
#define RUBY_FL_USHIFT      12
// https://github.com/ruby/ruby/blob/523857bfcb0f0cdfd1ed7faa09b9c59a0266e7e2/internal/imemo.h#L18
#define IMEMO_MASK          0x0f
// https://github.com/ruby/ruby/blob/523857bfcb0f0cdfd1ed7faa09b9c59a0266e7e2/internal/imemo.h#L33-L37
#define IMEMO_SVAR          2
#define IMEMO_MENT          6

// https://github.com/ruby/ruby/blob/v3_4_5/vm_core.h#L1380-L1385
#define VM_FRAME_MAGIC_MASK  0x7fff0001
#define VM_FRAME_MAGIC_CFUNC 0x55550001

// Save on read ops by reading the whole control frame struct
// as technically this reads too much memory
typedef struct rb_control_frame_struct {
  const void *pc;          // cfp[0]
  void *_sp;               // cfp[1]
  const void *iseq;        // cfp[2]
  void *_self;             // cfp[3] / block[0]
  const void *ep;          // cfp[4] / block[1]
  const void *_block_code; // cfp[5] / block[2] -- iseq, ifunc, or forwarded block handler
  void *_jit_return;       // cfp[6] -- return address for JIT code
  void *_padding;          // cfp[7] / VALUE *bp_check if compiled with VM_DEBUG_BP_CHECK
} rb_control_frame_t;

// Save on reads by putting all of these variables into one struct:
// #define VM_ENV_DATA_INDEX_ME_CREF    (-2) /* ep[-2] */
// #define VM_ENV_DATA_INDEX_SPECVAL    (-1) /* ep[-1] */
// #define VM_ENV_DATA_INDEX_FLAGS      ( 0) /* ep[ 0] */
typedef struct vm_env_struct {
  const void *me_cref;
  const void *specval;
  const void *flags;
} vm_env_t;

// Record a Ruby frame
// frame_type is encoded into the "file" attribute of frame in the spare bits
// is may change in the future.
static EBPF_INLINE ErrorCode
push_ruby(UnwindState *state, Trace *trace, u8 frame_type, u64 file, u64 line, u64 iseq_addr)
{
  u64 *data = push_frame(state, trace, FRAME_MARKER_RUBY, FRAME_FLAG_PID_SPECIFIC, file, 3);
  if (!data) {
    return ERR_STACK_LENGTH_EXCEEDED;
  }
  data[0] = frame_type;
  data[1] = line;
  data[2] = iseq_addr;
  return ERR_OK;
}

// Read a single Ruby frame
// This code is based on ruby's own rb_profile_frames, which internally calls
// thread_profile_frames once it has the execution context.
// https://github.com/ruby/ruby/blob/v3_4_7/vm_backtrace.c#L1728-L1770
// It checks if it is a cframe, looks for a callable method entry, or else
// pushes a bare iseq.
static EBPF_INLINE ErrorCode read_ruby_frame(
  PerCPURecord *record, const RubyProcInfo *rubyinfo, void *stack_ptr, int *next_unwinder)
{
  // Type of frame we found and are pushing (encoded in upper bits of Frame
  u8 frame_type;
  // Actual frame address of the given type
  u64 frame_addr;
  // Address of the cfp->iseq, used to get the line number using the pc
  u64 iseq_addr = 0;
  u64 pc        = 0;

  Trace *trace     = &record->trace;
  u64 rbasic_flags = 0;
  u64 imemo_mask   = 0;
  u64 me_or_cref   = 0;
  u64 svar_cref    = 0;
  void *current_ep = NULL;
  u64 frame_flags  = 0;
  bool cfunc       = false;

  u64 ep_check = 0;

  vm_env_t vm_env;
  rb_control_frame_t control_frame;

  // Read the control frame pointer
  if (bpf_probe_read_user(&control_frame, sizeof(rb_control_frame_t), (void *)(stack_ptr))) {
    increment_metric(metricID_UnwindRubyErrReadStackPtr);
    return ERR_RUBY_READ_STACK_PTR;
  }
  current_ep = (void *)control_frame.ep;
  pc         = (u64)control_frame.pc;

  // this code emulates ruby's rb_vm_frame_method_entry, which is called by
  // rb_vm_frame_method_entry to check the frame for a callable method entry, CME
  // https://github.com/ruby/ruby/blob/v3_4_7/vm_insnhelper.c#L769
  UNROLL for (ep_check = 0; ep_check < MAX_EP_CHECKS; ++ep_check)
  {
    // On every iteration except the first, get the ep from specval only if
    // it is non-local.
    if (ep_check > 0) {
      if (!((u64)vm_env.flags & VM_ENV_FLAG_LOCAL)) {
        // https://github.com/ruby/ruby/blob/v3_4_5/vm_core.h#L1355
        current_ep = (void *)((u64)vm_env.specval & ~0x03);
      } else {
        break;
      }
    }

    frame_addr = 0;
    frame_type = RUBY_FRAME_TYPE_NONE;
    cfunc      = false;

    if (bpf_probe_read_user(
          &vm_env, sizeof(vm_env), (void *)(current_ep - sizeof(vm_env) + sizeof(void *)))) {
      DEBUG_PRINT("ruby: failed to get vm env");
      increment_metric(metricID_UnwindRubyErrReadEp);
      return ERR_RUBY_READ_EP;
    }

    me_or_cref = (u64)vm_env.me_cref;
    // Only check the flags from the "root" env
    if (frame_flags == 0) {
      frame_flags = (u64)vm_env.flags;
    }
    cfunc = (((frame_flags & VM_FRAME_MAGIC_MASK) == VM_FRAME_MAGIC_CFUNC) || pc == 0);

    if (!cfunc) {
      // Read the control frame iseq so we can get the line number
      if (control_frame.iseq == NULL) {
        increment_metric(metricID_UnwindRubyErrInvalidIseq);
        return ERR_RUBY_INVALID_ISEQ;
      }
      if (bpf_probe_read_user(
            &iseq_addr, sizeof(iseq_addr), (void *)(control_frame.iseq + rubyinfo->body))) {
        increment_metric(metricID_UnwindRubyErrReadIseqBody);
        return ERR_RUBY_READ_ISEQ_BODY;
      }
    }

    // this code emulate's ruby's check_method_entry to traverse the environment
    // until it finds a method entry. Since the function calls itself, the code
    // is a bit out of order to try and optimize running as few instructions as
    // possible, since this is in the M * N part of the loop and we want the code
    // to pass the kernel verifier.
    // https://github.com/ruby/ruby/blob/v3_4_7/vm_insnhelper.c#L743
    if (me_or_cref == 0)
      continue;

    if (bpf_probe_read_user(&rbasic_flags, sizeof(rbasic_flags), (void *)(me_or_cref))) {
      increment_metric(metricID_UnwindRubyErrReadRbasicFlags);
      return ERR_RUBY_READ_RBASIC_FLAGS;
    }

    // https://github.com/ruby/ruby/blob/3361aa5c7df35b1d1daea578fefec3addf29c9a6/internal/imemo.h#L165-L169
    imemo_mask = (rbasic_flags >> RUBY_FL_USHIFT) & IMEMO_MASK;

    if ((u64)vm_env.flags & VM_ENV_FLAG_LOCAL) {
      if (imemo_mask == IMEMO_SVAR) {
        if (bpf_probe_read_user(&svar_cref, sizeof(svar_cref), (void *)(me_or_cref + 8))) {
          increment_metric(metricID_UnwindRubyErrReadSvar);
          return ERR_RUBY_READ_SVAR;
        }
        me_or_cref = svar_cref;

        if (bpf_probe_read_user(&rbasic_flags, sizeof(rbasic_flags), (void *)(me_or_cref))) {
          increment_metric(metricID_UnwindRubyErrReadRbasicFlags);
          return ERR_RUBY_READ_RBASIC_FLAGS;
        }
        imemo_mask = (rbasic_flags >> RUBY_FL_USHIFT) & IMEMO_MASK;
      }
    }

    if (imemo_mask == IMEMO_MENT)
      break;
  }

  if (ep_check >= MAX_EP_CHECKS)
    return ERR_RUBY_READ_CME_MAX_EP;

  if (imemo_mask == IMEMO_MENT) {
    frame_addr = me_or_cref;

    if (cfunc) {
      if (rubyinfo->version < 0x20600) {
        // With Ruby version 2.6 the scope of our entry symbol ruby_current_execution_context_ptr
        // got extended. We need this extension to jump back unwinding Ruby VM frames if we
        // continue at this point with unwinding native frames.
        // As this is not available for Ruby versions < 2.6 we just push the cfunc frame and
        // continue unwinding Ruby VM frames. Due to this issue, the ordering of Ruby and native
        // frames will almost certainly be incorrect for Ruby versions < 2.6.
        frame_type = RUBY_FRAME_TYPE_CME_CFUNC;
      } else if (record->rubyUnwindState.jit_detected) {
        // If we detected a jit frame and are now in a cfunc, push the c frame
        // as we can no longer unwind native anymore
        frame_type = RUBY_FRAME_TYPE_CME_CFUNC;
      } else {
        // We save this cfp on in the "Record" entry, and when we start the unwinder
        // again we'll push it so that the order is correct and the cfunc "owns" any native code we
        // unwound rather than eliding it
        record->rubyUnwindState.cfunc_saved_frame = frame_addr;

        *next_unwinder = PROG_UNWIND_NATIVE;
        return ERR_OK;
      }
    } else {
      // Now we must further verify that it is ISEQ type, but do it out of the loop
      // https://github.com/ruby/ruby/blob/v3_4_5/vm_backtrace.c#L1736
      u64 method_def = 0;
      u8 method_type = 0;

      if (bpf_probe_read_user(
            &method_def, sizeof(method_def), (void *)(frame_addr + rubyinfo->cme_method_def))) {
        increment_metric(metricID_UnwindRubyErrReadMethodDef);
        return ERR_RUBY_READ_METHOD_DEF;
      }

      if (bpf_probe_read_user(&method_type, sizeof(method_type), (void *)(method_def))) {
        increment_metric(metricID_UnwindRubyErrReadMethodType);
        return ERR_RUBY_READ_METHOD_TYPE;
      }

      method_type &= 0xf;
      if (method_type == VM_METHOD_TYPE_ISEQ) {
        frame_type = RUBY_FRAME_TYPE_CME_ISEQ;
      }
    }
  }

  // Fallback to just reading the iseq if we couldn't detect a supported CME type
  if (frame_type == RUBY_FRAME_TYPE_NONE) {
    frame_addr = iseq_addr;
    frame_type = RUBY_FRAME_TYPE_ISEQ;
  }

  // For symbolization of the frame we forward the information about the CME,
  // or plain iseq to userspace, along with the pc so we can get line information.
  // From this we can then extract information like file or function name and line number.
  ErrorCode error = push_ruby(&record->state, trace, frame_type, frame_addr, pc, iseq_addr);
  if (error) {
    DEBUG_PRINT("ruby: failed to push frame");
    return error;
  }
  increment_metric(metricID_UnwindRubyFrames);

  return ERR_OK;
}

// walk_ruby_stack processes a Ruby VM stack, extracts information from the individual frames and
// pushes this information to user space for symbolization of these frames.
//
// Ruby unwinder workflow:
// From the current execution context struct [0] we can get pointers to the current Ruby VM stack
// as well as to the current call frame pointer (cfp).
// On the Ruby VM stack we have for each cfp one struct [1]. These cfp structs then point to
// instruction sequence (iseq) structs [2] that store the information about file and function name
// that we forward to user space for the symbolization process of the frame, or they may
// point to a Callable Method Entry (CME) [3]. In the Ruby's own backtrace functions, they
// may store either of these [4]. In the case of a CME, since ruby 3.3.0 [5] class names
// have been stored as an easily accessible struct member on the classext, accessible
// through the CME. We will check the frame for IMEMO_MENT to see if it is a CME frame,
// which makes it possible to determine the classname. The iseq body is accessible through
// additional indirection of the CME, so we can still get the file and function names
// through the existing method.
//
// If the frame is a CME, we will push it with a separate frame type to userspace
// so that the Symbolizer will know what type of pointer we have given it, and
// can search the struct at the right offsets for the classpath and iseq body.
//
// If the frame is the plain iseq type, the original logic of just extracting the
// function and file names and line numbers is executed.

// The frame values, and in particular the CMEs, are read in BPF because the CFP
// entries are volatile, and we cannot simply push the CFP into go as the control
// frame data will likely have changed if it is not read during the perf interrupt.
// This code approach also mimics how ruby's own backtrace function works:
// - Build up a frame buffer of CME or plain iseq entries, done while state
//   is guaranteed consistent during the perf interrupt. [4]
// - These more stable references can be converted to useful symbolic labels
//   out-of-band from the unwinding and sample collection. [6]
//
// [0] rb_execution_context_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L843
//
// [1] rb_control_frame_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L760
//
// [3] rb_callable_method_entry_struct
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/method.h#L63-L69
//
// [4] thread_profile_frames frame storage of CME or iseq members for a single backtrace
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/vm_backtrace.c#L1754-L1761
//
// [5] classpath stored as struct member instead of ivar
// https://github.com/ruby/ruby/commit/abff5f62037284024aaf469fc46a6e8de98fa1e3
//
// [6] rb_profile_frame_full_label describes how the collected samples can be symbolized on the go
// side
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/vm_backtrace.c#L1995

static EBPF_INLINE ErrorCode walk_ruby_stack(
  PerCPURecord *record,
  const RubyProcInfo *rubyinfo,
  const void *current_ctx_addr,
  int *next_unwinder)
{
  if (!current_ctx_addr) {
    *next_unwinder = get_next_unwinder_after_interpreter();
    return ERR_OK;
  }

  Trace *trace   = &record->trace;
  *next_unwinder = PROG_UNWIND_STOP;

  // stack_ptr points to the frame of the Ruby VM call stack that will be unwound next
  void *stack_ptr        = record->rubyUnwindState.stack_ptr;
  // last_stack_frame points to the last frame on the Ruby VM stack we want to process
  void *last_stack_frame = record->rubyUnwindState.last_stack_frame;

  if (!stack_ptr || !last_stack_frame) {
    // stack_ptr_current points to the current frame in the Ruby VM call stack
    void *stack_ptr_current;
    // stack_size does not reflect the number of frames on the Ruby VM stack
    // but contains the current stack size in words.
    // stack_size = size in word (size in bytes / sizeof(VALUE))
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L846
    size_t stack_size;

    if (bpf_probe_read_user(
          &stack_ptr_current,
          sizeof(stack_ptr_current),
          (void *)(current_ctx_addr + rubyinfo->vm_stack))) {
      increment_metric(metricID_UnwindRubyErrReadStackPtr);
      return ERR_RUBY_READ_STACK_PTR;
    }

    if (bpf_probe_read_user(
          &stack_size, sizeof(stack_size), (void *)(current_ctx_addr + rubyinfo->vm_stack_size))) {
      increment_metric(metricID_UnwindRubyErrReadStackSize);
      return ERR_RUBY_READ_STACK_SIZE;
    }

    // Calculate the base of the stack so we can calculate the number of frames from it.
    // Ruby places two dummy frames on the Ruby VM stack in which we are not interested.
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L477-L485
    last_stack_frame = stack_ptr_current + (rubyinfo->size_of_value * stack_size) -
                       (2 * rubyinfo->size_of_control_frame_struct);

    if (bpf_probe_read_user(
          &stack_ptr, sizeof(stack_ptr), (void *)(current_ctx_addr + rubyinfo->cfp))) {
      increment_metric(metricID_UnwindRubyErrReadCfp);
      return ERR_RUBY_READ_CFP;
    }
  }

  ErrorCode error;
  // If we entered native unwinding because we saw a cfunc frame, lets push that
  // frame now so it can take "ownership" of the native code that was unwound
  if (record->rubyUnwindState.cfunc_saved_frame != 0) {
    error = push_ruby(
      &record->state,
      trace,
      RUBY_FRAME_TYPE_CME_CFUNC,
      record->rubyUnwindState.cfunc_saved_frame,
      0,
      0);
    if (error) {
      return error;
    }
    record->rubyUnwindState.cfunc_saved_frame = 0;
  }

  if (
    rubyinfo->jit_start > 0 && record->state.pc > rubyinfo->jit_start &&
    record->state.pc < rubyinfo->jit_end) {
    record->rubyUnwindState.jit_detected = true;

    // If the first frame is a jit PC, the leaf ruby frame should be the jit "owner"
    // the cpu PC is also pushed as the address,
    // as in theory this can be used to symbolize the JIT frame later
    if (trace->num_frames == 0) {
      ErrorCode error =
        push_ruby(&record->state, trace, RUBY_FRAME_TYPE_JIT, (u64)record->state.pc, 0, 0);
      if (error) {
        return error;
      }
    }
  }

  UNROLL for (u32 i = 0; i < FRAMES_PER_WALK_RUBY_STACK; ++i)
  {
    error = read_ruby_frame(record, rubyinfo, stack_ptr, next_unwinder);
    if (error != ERR_OK)
      return error;

    if (last_stack_frame <= stack_ptr) {
      // We have processed all frames in the Ruby VM and can stop here.
      // if this process has been JIT'd, the PC is invalid and we cannot resume native unwinding so
      // we are done
      *next_unwinder = record->rubyUnwindState.jit_detected ? PROG_UNWIND_STOP : PROG_UNWIND_NATIVE;
      goto save_state;
    } else {
      // If we aren't at the end, advance the stack pointer to continue from the next frame
      stack_ptr += rubyinfo->size_of_control_frame_struct;
    }
    // If the next winder is native, save state and move to next unwinder
    if (*next_unwinder == PROG_UNWIND_NATIVE)
      goto save_state;
  }

  *next_unwinder = PROG_UNWIND_RUBY;
save_state:
  // Store the current progress in the Ruby unwind state so we can continue walking the stack
  // after the tail call.
  record->rubyUnwindState.stack_ptr        = stack_ptr;
  record->rubyUnwindState.last_stack_frame = last_stack_frame;

  return ERR_OK;
}

// unwind_ruby is the tail call destination for PROG_UNWIND_RUBY.
static EBPF_INLINE int unwind_ruby(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  int unwinder           = get_next_unwinder_after_interpreter();
  ErrorCode error        = ERR_OK;
  u32 pid                = record->trace.pid;
  RubyProcInfo *rubyinfo = bpf_map_lookup_elem(&ruby_procs, &pid);
  if (!rubyinfo) {
    DEBUG_PRINT("No Ruby introspection data");
    error = ERR_RUBY_NO_PROC_INFO;
    increment_metric(metricID_UnwindRubyErrNoProcInfo);
    goto exit;
  }

  increment_metric(metricID_UnwindRubyAttempts);

  // Pointer for an address to a rb_execution_context_struct struct.
  void *current_ctx_addr = NULL;

  if (rubyinfo->current_ec_tpbase_tls_offset != 0) {
    // With Ruby 3.x and its internal change of the execution model, we can no longer
    // access rb_execution_context_struct directly. We will look up the
    // ruby_current_ec from thread local storage, analogous to how it is done
    // in ruby itself
    // https://github.com/ruby/ruby/blob/6c0315d99a93bdea947f821bd337000420ab41d1/vm_core.h#L2024
    u64 tsd_base;
    if (tsd_get_base((void **)&tsd_base) != 0) {
      DEBUG_PRINT("ruby: failed to get TSD base for TLS symbol lookup");
      error = ERR_RUBY_READ_TSD_BASE;
      goto exit;
    }

    u64 tls_current_ec_addr = tsd_base + rubyinfo->current_ec_tpbase_tls_offset;

    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)(tls_current_ec_addr))) {
      goto exit;
    }
  } else if (rubyinfo->version >= 0x30000) {
    void *single_main_ractor = NULL;
    if (bpf_probe_read_user(
          &single_main_ractor, sizeof(single_main_ractor), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }

    if (bpf_probe_read_user(
          &current_ctx_addr,
          sizeof(current_ctx_addr),
          (void *)(single_main_ractor + rubyinfo->running_ec))) {
      goto exit;
    }
  } else {
    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }
  }

  if (!current_ctx_addr) {
    goto exit;
  }

  error = walk_ruby_stack(record, rubyinfo, current_ctx_addr, &unwinder);
exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_ruby)
