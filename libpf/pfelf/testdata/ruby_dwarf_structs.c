#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Snippets of more complicated structs from ruby.h

#define IMMEDIATE_TABLE_SIZE 54 /* a multiple of 9, and < 128 */
#define USE_RJIT 1

typedef uintptr_t VALUE;
typedef uintptr_t ID;
typedef uint32_t id_key_t;
typedef uintptr_t iseq_bits_t;
typedef uintptr_t
    rb_jit_func_t; // not sure where it is actually defined, pahole says it is 8
typedef uintptr_t
    rb_event_hook_func_t; // size of a function pointer, pahole says 8
typedef uint32_t rb_event_flag_t;
typedef signed long rb_snum_t;

#include <pthread.h>
typedef pthread_mutex_t rb_nativethread_lock_t;
typedef pthread_cond_t rb_nativethread_cond_t;

struct RBasic {
  VALUE flags;
  const VALUE klass;

#if RBASIC_SHAPE_ID_FIELD
  VALUE shape_id;
#endif
};

struct RString {
  struct RBasic basic;
  long len;
  union {
    struct {
      char *ptr;
      union {
        long capa;
        VALUE shared;
      } aux;
    } heap;

    struct {
      char ary[1];
    } embed;
  } as;
};

struct RArray {
  struct RBasic basic;
  union {
    struct {
      long len;
      union {
        long capa;
#if defined(__clang__) /* <- clang++ is sane */ ||                             \
    !defined(__cplusplus) /* <- C99 is sane */ ||                              \
    (__cplusplus > 199711L) /* <- C++11 is sane */
        const
#endif
            VALUE shared_root;
      } aux;
      const VALUE *ptr;
    } heap;
    const VALUE ary[1];
  } as;
};

struct iseq_insn_info_entry {
  int line_no;
#ifdef USE_ISEQ_NODE_ID
  int node_id;
#endif
  rb_event_flag_t events;
};

typedef struct rb_id_item {
  id_key_t key;
  int collision;
  VALUE val;
} item_t;

struct rb_id_table {
  int capa;
  int num;
  int used;
  item_t *items;
};

typedef struct rb_code_position_struct {
  int lineno;
  int column;
} rb_code_position_t;

typedef struct rb_code_location_struct {
  rb_code_position_t beg_pos;
  rb_code_position_t end_pos;
} rb_code_location_t;

typedef struct rb_iseq_location_struct {
  VALUE pathobj;    /* String (path) or Array [path, realpath]. Frozen. */
  VALUE base_label; /* String */
  VALUE label;      /* String */
  int first_lineno;
  int node_id;
  rb_code_location_t code_location;
} rb_iseq_location_t;

enum rb_iseq_type {
  ISEQ_TYPE_TOP,
  ISEQ_TYPE_METHOD,
  ISEQ_TYPE_BLOCK,
  ISEQ_TYPE_CLASS,
  ISEQ_TYPE_RESCUE,
  ISEQ_TYPE_ENSURE,
  ISEQ_TYPE_EVAL,
  ISEQ_TYPE_MAIN,
  ISEQ_TYPE_PLAIN
};

struct rb_iseq_struct;
typedef struct rb_iseq_struct rb_iseq_t;

struct rb_iseq_constant_body {
  enum rb_iseq_type type;

  unsigned int iseq_size;
  VALUE *iseq_encoded; /* encoded iseq (insn addr and operands) */

  struct {
    struct {
      unsigned int has_lead : 1;
      unsigned int has_opt : 1;
      unsigned int has_rest : 1;
      unsigned int has_post : 1;
      unsigned int has_kw : 1;
      unsigned int has_kwrest : 1;
      unsigned int has_block : 1;

      unsigned int ambiguous_param0 : 1; /* {|a|} */
      unsigned int accepts_no_kwarg : 1;
      unsigned int ruby2_keywords : 1;
      unsigned int anon_rest : 1;
      unsigned int anon_kwrest : 1;
      unsigned int use_block : 1;
      unsigned int forwardable : 1;
    } flags;

    unsigned int size;

    int lead_num;
    int opt_num;
    int rest_start;
    int post_start;
    int post_num;
    int block_start;

    const VALUE *opt_table; /* (opt_num + 1) entries. */
    /* opt_num and opt_table:
     *
     * def foo o1=e1, o2=e2, ..., oN=eN
     * #=>
     *   # prologue code
     *   A1: e1
     *   A2: e2
     *   ...
     *   AN: eN
     *   AL: body
     * opt_num = N
     * opt_table = [A1, A2, ..., AN, AL]
     */

    const struct rb_iseq_param_keyword {
      int num;
      int required_num;
      int bits_start;
      int rest_start;
      const ID *table;
      VALUE *default_values;
    } *keyword;
  } param;

  rb_iseq_location_t location;

  /* insn info, must be freed */
  struct iseq_insn_info {
    const struct iseq_insn_info_entry *body;
    unsigned int *positions;
    unsigned int size;
    // #if VM_INSN_INFO_TABLE_IMPL == 2
    struct succ_index_table *succ_index_table;
    // #endif
  } insns_info;

  const ID *local_table; /* must free */

  /* catch table */
  struct iseq_catch_table *catch_table;

  /* for child iseq */
  const struct rb_iseq_struct *parent_iseq;
  struct rb_iseq_struct *local_iseq; /* local_iseq->flip_cnt can be modified */

  union iseq_inline_storage_entry
      *is_entries;                /* [ TS_IVC | TS_ICVARC | TS_ISE | TS_IC ] */
  struct rb_call_data *call_data; // struct rb_call_data calls[ci_size];

  struct {
    rb_snum_t flip_count;
    VALUE script_lines;
    VALUE coverage;
    VALUE pc2branchindex;
    VALUE *original_iseq;
  } variable;

  unsigned int local_table_size;
  unsigned int ic_size;     // Number of IC caches
  unsigned int ise_size;    // Number of ISE caches
  unsigned int ivc_size;    // Number of IVC caches
  unsigned int icvarc_size; // Number of ICVARC caches
  unsigned int ci_size;
  unsigned int stack_max; /* for stack overflow check */

  unsigned int builtin_attrs; // Union of rb_builtin_attr

  bool prism; // ISEQ was generated from prism compiler

  union {
    iseq_bits_t *list; /* Find references for GC */
    iseq_bits_t single;
  } mark_bits;

  struct rb_id_table *outer_variables;

  const rb_iseq_t *mandatory_only_iseq;

#if USE_RJIT || USE_YJIT
  // Function pointer for JIT code on jit_exec()
  rb_jit_func_t jit_entry;
  // Number of calls on jit_exec()
  long unsigned jit_entry_calls;
#endif

#if USE_YJIT
  // Function pointer for JIT code on jit_exec_exception()
  rb_jit_func_t jit_exception;
  // Number of calls on jit_exec_exception()
  long unsigned jit_exception_calls;
#endif

#if USE_RJIT
  // RJIT stores some data on each iseq.
  VALUE rjit_blocks;
#endif

#if USE_YJIT
  // YJIT stores some data on each iseq.
  void *yjit_payload;
  // Used to estimate how frequently this ISEQ gets called
  uint64_t yjit_calls_at_interv;
#endif
};

struct rb_iseq_struct {
  VALUE flags;   /* 1 */
  VALUE wrapper; /* 2 */

  struct rb_iseq_constant_body *body; /* 3 */

  // ...
};

typedef struct rb_control_frame_struct {
  const VALUE *pc;       /* cfp[0] */
  VALUE *sp;             /* cfp[1] */
  const rb_iseq_t *iseq; /* cfp[2] */
  VALUE self;            /* cfp[3] / block[0] */
  const VALUE *ep;       /* cfp[4] / block[1] */
  const void *block_code;
      /* cfp[5] / block[2] */ /* iseq or ifunc or forwarded block handler */
  VALUE *__bp__;
      /* cfp[6] */ /* outside vm_push_frame, use vm_base_ptr instead. */

#if VM_DEBUG_BP_CHECK
  VALUE *bp_check; /* cfp[7] */
#endif
} rb_control_frame_t;

typedef struct rb_execution_context_struct {
  /* execution information */
  VALUE *vm_stack;      /* must free, must mark */
  size_t vm_stack_size; /* size in word (byte size / sizeof(VALUE)) */
  rb_control_frame_t *cfp;
  // ...
} rb_execution_context_t;

struct succ_index_table {
  uint64_t imm_part[IMMEDIATE_TABLE_SIZE / 9];
  struct succ_dict_block {
    unsigned int rank;
    uint64_t small_block_ranks; /* 9 bits * 7 = 63 bits */
    uint64_t bits[512 / 64];
  } succ_part[0];
};

typedef enum {
  RUBY_EVENT_HOOK_FLAG_SAFE = 0x01,
  RUBY_EVENT_HOOK_FLAG_DELETED = 0x02,
  RUBY_EVENT_HOOK_FLAG_RAW_ARG = 0x04
} rb_event_hook_flag_t;

// This type is too complicated, just jamming a dummy struct in that is the same
// size
typedef struct rb_thread_struct {
  uint8_t dummy_array[480];
} rb_thread_t;

typedef struct rb_event_hook_struct {
  rb_event_hook_flag_t hook_flags;
  rb_event_flag_t events;
  rb_event_hook_func_t func;
  VALUE data;
  struct rb_event_hook_struct *next;

  struct {
    rb_thread_t *th;
    unsigned int target_line;
  } filter;
} rb_event_hook_t;

typedef struct rb_hook_list_struct {
  struct rb_event_hook_struct *hooks;
  rb_event_flag_t events;
  unsigned int running;
  bool need_clean;
  bool is_local;
} rb_hook_list_t;

struct rb_ractor_pub {
  VALUE self;
  uint32_t id;
  rb_hook_list_t hooks;
};

struct ccan_list_node {
  struct ccan_list_node *next, *prev;
};

struct ccan_list_head {
  struct ccan_list_node n;
};

struct rb_ractor_struct;
typedef struct rb_ractor_struct rb_ractor_t;

struct rb_thread_sched {
  rb_nativethread_lock_t lock_;
#if VM_CHECK_MODE
  struct rb_thread_struct *lock_owner;
#endif
  struct rb_thread_struct *running; // running thread or NULL
  bool is_running;
  bool is_running_timeslice;
  bool enable_mn_threads;

  struct ccan_list_head readyq;
  int readyq_cnt;
  // ractor scheduling
  struct ccan_list_node grq_node;
};

// just want this type, don't care about the members, just the size
struct rb_ractor_basket {
  uint8_t dummy_array[32];
};

struct rb_ractor_queue {
  struct rb_ractor_basket *baskets;
  int start;
  int cnt;
  int size;
  unsigned int serial;
  unsigned int reserved_cnt;
};

enum rb_ractor_wait_status {
  wait_none = 0x00,
  wait_receiving = 0x01,
  wait_taking = 0x02,
  wait_yielding = 0x04,
  wait_moving = 0x08,
};

enum rb_ractor_wakeup_status {
  wakeup_none,
  wakeup_by_send,
  wakeup_by_yield,
  wakeup_by_take,
  wakeup_by_close,
  wakeup_by_interrupt,
  wakeup_by_retry,
};

struct rb_ractor_sync {
  // ractor lock
  rb_nativethread_lock_t lock;
#if RACTOR_CHECK_MODE > 0
  VALUE locked_by;
#endif

  bool incoming_port_closed;
  bool outgoing_port_closed;

  // All sent messages will be pushed into recv_queue
  struct rb_ractor_queue recv_queue;

  // The following ractors waiting for the yielding by this ractor
  struct rb_ractor_queue takers_queue;

  // Enabled if the ractor already terminated and not taken yet.
  struct rb_ractor_basket will_basket;

  struct ractor_wait {
    enum rb_ractor_wait_status status;
    enum rb_ractor_wakeup_status wakeup_status;
    rb_thread_t *waiting_thread;
  } wait;
};

struct rb_ractor_struct {
  struct rb_ractor_pub pub;
  struct rb_ractor_sync sync;

  VALUE receiving_mutex;

  // vm wide barrier synchronization
  rb_nativethread_cond_t barrier_wait_cond;
  // thread management
  struct {
    struct ccan_list_head set;
    unsigned int cnt;
    unsigned int blocking_cnt;
    unsigned int sleeper;
    struct rb_thread_sched sched;
    rb_execution_context_t *running_ec;
    // ...
  } threads;
  // ...
}; // rb_ractor_t is defined in vm_core.h

int main(int argc, char *argv[]) {
  struct succ_index_table _idx_table;
  struct rb_execution_context_struct _exec_context;
  struct rb_control_frame_struct _control_frame;
  struct rb_iseq_struct _iseq_struct;
  struct RString _string;
  struct RArray _array;
  struct rb_ractor_struct _ractor;
  return 0;
}
