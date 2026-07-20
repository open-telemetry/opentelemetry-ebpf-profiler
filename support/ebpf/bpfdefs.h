#ifndef OPTI_BPFDEFS_H
#define OPTI_BPFDEFS_H

#include "kernel.h"

// with_debug_output is declared in native_stack_trace.ebpf.c
extern u32 with_debug_output;

// UNUSED is a macro that marks a parameter or variable as intentionally unused.
// It prevents compiler warnings about unused variables while keeping them in the code.
#define UNUSED __attribute__((unused))

// BTF-style map definition macros from tools/lib/bpf/bpf_helpers.h
#define __uint(name, val)  int(*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#if defined(TESTING_COREDUMP)

  // BPF_RODATA_VAR declares a global variable in the .rodata section,
  // ensuring it's not optimized away by the compiler or linker.
  //
  // Arguments:
  //   _type: The data type of the variable (e.g., u32, int, struct my_config).
  //   _name: The name of the global variable.
  //   _value: The initial value for the variable.
  #define BPF_RODATA_VAR(_type, _name, _value) _type _name = _value;

  // tools/coredump uses CGO to build the eBPF code. Provide here the glue to
  // dispatch the BPF API to helpers implemented in ebpfhelpers.go.
  #define SEC(NAME)
  #define EBPF_INLINE

  #define printt(fmt, ...)      bpf_log(fmt, ##__VA_ARGS__)
  #define DEBUG_PRINT(fmt, ...) bpf_log(fmt, ##__VA_ARGS__)

// BPF helpers. Mostly stubs to dispatch the call to Go code with the context ID.
int bpf_tail_call(void *ctx, void *map, int index);
unsigned long long bpf_ktime_get_ns(void);
int bpf_get_current_comm(void *, int);
int bpf_perf_event_output(void *, void *, unsigned long long, void *, int);
long bpf_ringbuf_output(void *, void *, u64, u64);
static inline struct task_struct *bpf_get_current_task_btf(void)
{
  return NULL;
}

static inline long bpf_find_vma(
  UNUSED struct task_struct *task,
  UNUSED u64 addr,
  UNUSED void *callback_fn,
  UNUSED void *callback_ctx,
  UNUSED u64 flags)
{
  return 0;
}

static inline long bpf_probe_read_user(void *buf, u32 sz, const void *ptr)
{
  long __bpf_probe_read_user(u64, void *, u32, const void *);
  return __bpf_probe_read_user(__cgo_ctx->id, buf, sz, ptr);
}

static inline long bpf_probe_read_user_with_test_fault(void *buf, u32 sz, const void *ptr)
{
  long __bpf_probe_read_user_with_test_fault(u64, void *, u32, const void *);
  return __bpf_probe_read_user_with_test_fault(__cgo_ctx->id, buf, sz, ptr);
}

static inline long bpf_probe_read_kernel(UNUSED void *buf, UNUSED u32 sz, UNUSED const void *ptr)
{
  return -1;
}

static inline u64 bpf_get_current_pid_tgid(void)
{
  return __cgo_ctx->id;
}

// PID-namespace translation is a no-op for coredump analysis (a single-process
// snapshot has no nested namespaces). Provide fast-path stubs so the shared
// eBPF sources that call these helpers also compile under TESTING_COREDUMP.
static inline u32 get_pid_in_profiler_ns(void)
{
  return (u32)(bpf_get_current_pid_tgid() >> 32);
}

static inline bool is_our_analysis_task(u32 caller_pid)
{
  return caller_pid == (u32)(bpf_get_current_pid_tgid() >> 32);
}

static inline void *bpf_map_lookup_elem(void *map, const void *key)
{
  void *__bpf_map_lookup_elem(u64, void *, const void *);
  return __bpf_map_lookup_elem(__cgo_ctx->id, map, key);
}

static inline int bpf_map_update_elem(
  UNUSED void *map, UNUSED const void *key, UNUSED const void *val, UNUSED u64 flags)
{
  return -1;
}

static inline int bpf_map_delete_elem(UNUSED void *map, UNUSED const void *key)
{
  return -1;
}

static inline u32 bpf_get_smp_processor_id(void)
{
  return 0;
}

static inline long
bpf_get_stack(UNUSED void *ctx, UNUSED void *buf, UNUSED u32 size, UNUSED u64 flags)
{
  return -1;
}

#else // TESTING_COREDUMP

  // Native eBPF build

  // BPF_RODATA_VAR declares a global variable in the .rodata section,
  // ensuring it's not optimized away by the compiler or linker.
  //
  // Arguments:
  //   _type: The data type of the variable (e.g., u32, int, struct my_config).
  //   _name: The name of the global variable.
  //   _value: The initial value for the variable.
  #define BPF_RODATA_VAR(_type, _name, _value)                                                     \
    _type _name __attribute__((section(".rodata.var"), used)) = _value;

// definitions of bpf helper functions we need, as found in
// https://elixir.bootlin.com/linux/v4.11/source/samples/bpf/bpf_helpers.h

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, u64 flags) = (void *)
  BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key)     = (void *)BPF_FUNC_map_delete_elem;
static unsigned long long (*bpf_ktime_get_ns)(void)         = (void *)BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) = (void *)BPF_FUNC_get_current_comm;
static void (*bpf_tail_call)(void *ctx, void *map, int index) = (void *)BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_current_task)(void)       = (void *)BPF_FUNC_get_current_task;
static struct task_struct *(*bpf_get_current_task_btf)(void)  = (void *)
  BPF_FUNC_get_current_task_btf;
static long (*bpf_find_vma)(
  struct task_struct *task, u64 addr, void *callback_fn, void *callback_ctx, u64 flags) = (void *)
  BPF_FUNC_find_vma;
static int (*bpf_perf_event_output)(
  void *ctx, void *map, unsigned long long flags, void *data, int size) = (void *)
  BPF_FUNC_perf_event_output;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, u64 size, u64 flags) = (void *)
  BPF_FUNC_ringbuf_output;
static u32 (*bpf_get_smp_processor_id)(void) = (void *)BPF_FUNC_get_smp_processor_id;
static long (*bpf_get_stack)(void *ctx, void *buf, u32 size, u64 flags) = (void *)
  BPF_FUNC_get_stack;
static unsigned long long (*bpf_get_prandom_u32)(void) = (void *)BPF_FUNC_get_prandom_u32;

__attribute__((format(printf, 1, 3))) static int (*bpf_trace_printk)(
  const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

static long (*bpf_probe_read_user)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_kernel)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read_kernel;
static long (*bpf_send_signal_thread)(u32 sig) = (void *)BPF_FUNC_send_signal_thread;

  #define bpf_probe_read_user_with_test_fault bpf_probe_read_user

// PID namespace translation: ports the kernel's task_tgid_nr_ns() helper to
// BPF so PIDs emitted to userspace match the profiler's /proc view when it
// runs in a nested PID namespace (e.g. a kind/minikube DaemonSet). When
// profiler_pidns_level == 0 the helpers short-circuit to
// bpf_get_current_pid_tgid() >> 32, so flat host / EKS deployments are
// unchanged.
//
// task_struct / struct pid / struct upid offsets are filled from BTF at load
// time by parsePidStructLayout(); profiler_pidns_level is discovered once at
// startup by the read_pid_level analysis probe.
extern u32 task_thread_pid_offset;
extern u32 task_group_leader_offset;
extern u32 pid_level_offset;
extern u32 pid_numbers_offset;
extern u32 upid_size;
extern u32 upid_nr_offset;
extern u32 profiler_pidns_level;

  // Upper bound on PID-ns nesting we ever expect to walk. Used to constrain
  // arithmetic the verifier can't otherwise bound.
  #define MAX_PID_NS_LEVELS                   8

// pidns_translation_available is true when parsePidStructLayout() populated the
// task_struct / pid layout offsets. Without them, the walk helpers return
// 0 / false and we fall back to the kernel-root PID for compatibility with
// pre-4.19 kernels and kernels without BTF.
static inline __attribute__((__always_inline__)) bool pidns_translation_available(void)
{
  return task_thread_pid_offset != 0;
}

// current_task_tgid_at_level returns the TGID (i.e. what getpid(2) returns) of
// the on-CPU task as it appears in the PID namespace at depth `level`. Walks
// via task->group_leader->thread_pid so the result is the process TGID
// regardless of which thread of the process is currently on-CPU. This mirrors
// the kernel's task_tgid_nr_ns() and, crucially, works for any task whose
// namespace is at `level` OR DEEPER (e.g. a pod one level below the profiler),
// which is what the DaemonSet case needs. Returns 0 for kernel threads, for
// tasks shallower than `level`, or on any read failure.
static inline __attribute__((__always_inline__)) u32 current_task_tgid_at_level(u32 level)
{
  // Fast path: profiler at kernel-root pidns, or task walking unavailable
  // (pre-4.19 / no BTF). Either way the kernel-root PID is what we want.
  if (level == 0 || !pidns_translation_available())
    return (u32)(bpf_get_current_pid_tgid() >> 32);

  void *task = (void *)bpf_get_current_task();
  void *leader;
  if (bpf_probe_read_kernel(&leader, sizeof(leader), task + task_group_leader_offset))
    return 0;
  if (!leader)
    return 0;

  void *pid;
  if (bpf_probe_read_kernel(&pid, sizeof(pid), leader + task_thread_pid_offset))
    return 0;
  if (!pid)
    return 0;

  u32 task_level;
  if (bpf_probe_read_kernel(&task_level, sizeof(task_level), pid + pid_level_offset))
    return 0;
  if (task_level > MAX_PID_NS_LEVELS || level > task_level)
    return 0;

  u32 nr;
  if (bpf_probe_read_kernel(
        &nr, sizeof(nr), pid + pid_numbers_offset + level * upid_size + upid_nr_offset))
    return 0;
  return nr;
}

// is_our_analysis_task filters the analysis probes to the userspace caller's
// process. Compares against the task's deepest-namespace TGID, which is what
// os.Getpid() returns in userspace. The previous kernel-root comparison only
// worked when the profiler ran in the kernel-root pidns.
static inline __attribute__((__always_inline__)) bool is_our_analysis_task(u32 caller_pid)
{
  // When PID-ns translation isn't available (pre-4.19 / no BTF), preserve the
  // pre-fix kernel-root comparison. This means the analysis probes only
  // succeed if the profiler runs in the kernel-root pidns, same as before.
  if (!pidns_translation_available())
    return caller_pid == (u32)(bpf_get_current_pid_tgid() >> 32);

  void *task = (void *)bpf_get_current_task();
  void *leader;
  if (bpf_probe_read_kernel(&leader, sizeof(leader), task + task_group_leader_offset))
    return false;
  if (!leader)
    return false;

  void *pid;
  if (bpf_probe_read_kernel(&pid, sizeof(pid), leader + task_thread_pid_offset))
    return false;
  if (!pid)
    return false;

  u32 task_level;
  if (bpf_probe_read_kernel(&task_level, sizeof(task_level), pid + pid_level_offset))
    return false;
  if (task_level > MAX_PID_NS_LEVELS)
    return false;

  u32 nr;
  if (bpf_probe_read_kernel(
        &nr, sizeof(nr), pid + pid_numbers_offset + task_level * upid_size + upid_nr_offset))
    return false;
  return nr == caller_pid;
}

// get_pid_in_profiler_ns returns the on-CPU task's TGID as the profiler's
// /proc view sees it. Drop-in replacement for `bpf_get_current_pid_tgid() >> 32`
// at sites that emit a PID for downstream /proc lookups.
static inline __attribute__((__always_inline__)) u32 get_pid_in_profiler_ns(void)
{
  return current_task_tgid_at_level(profiler_pidns_level);
}

  #define printt(fmt, ...)                                                                         \
    ({                                                                                             \
      static const char ____fmt[] = fmt;                                                           \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                   \
    })

  #define DEBUG_PRINT(fmt, ...)                                                                    \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0)) {                                                \
        printt(fmt, ##__VA_ARGS__);                                                                \
      }                                                                                            \
    })

  // Sends `SIGTRAP` to the current task, killing it and capturing a coredump.
  //
  // Only use this in code paths that you expect to be hit by a very specific process that you
  // intend to debug. Placing it into frequently taken code paths might otherwise take down
  // important system processes like sshd or your window manager. For frequently taken cases,
  // prefer using the `DEBUG_CAPTURE_COREDUMP_IF_TGID` macro.
  #define DEBUG_CAPTURE_COREDUMP()                                                                 \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0)) {                                                \
        bpf_send_signal_thread(SIGTRAP);                                                           \
      }                                                                                            \
    })

  // Like `DEBUG_CAPTURE_COREDUMP`, but only coredumps if the current task is a member of the
  // given thread group ID ("process").
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)                                                     \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0) && bpf_get_current_pid_tgid() >> 32 == (tgid)) {  \
        printt("coredumping process %d", (tgid));                                                  \
        bpf_send_signal_thread(SIGTRAP);                                                           \
      }                                                                                            \
    })

  // Definition of SEC as used by the Linux kernel in tools/lib/bpf/bpf_helpers.h for clang
  // compilations.
  #define SEC(name)                                                                                \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")      \
      __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")
  #define EBPF_INLINE __attribute__((__always_inline__))

#endif // !TESTING_COREDUMP

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#endif // OPTI_BPFDEFS_H
