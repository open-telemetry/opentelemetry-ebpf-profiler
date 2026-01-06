#include "bpfdefs.h"
#include "frametypes.h"
#include "stackdeltatypes.h"
#include "tracemgmt.h"
#include "types.h"
#include "tsd.h"

// todo belows are able to remove
#define KERNEL 0
#define MALLOC 1
#define CALLOC 2
#define REALLOC 3
#define MMAP 4
#define POSIX_MEMALIGN 5
#define VALLOC 6
#define MEMALIGN 7
#define PVALLOC 8
#define ALIGNED_ALLOC 9
#define FREE 10
#define MUNMAP 11
#define PYMALLOC 16
#define PYCALLOC 17
#define PYREALLOC 18


struct kmalloc_event {
    unsigned long pad;
    unsigned long call_site;
    const void *ptr;
    unsigned long bytes_req;
    unsigned long bytes_alloc;
    unsigned int gfp_flags;   // 分配标志
};

struct kfree_event {
    unsigned long pad;
    unsigned long call_site;
    const void *ptr;        // kfree 释放的地址
};

// 对应 kmem_cache_alloc tracepoint 的事件结构体
struct kmem_cache_alloc_event {
    unsigned long pad;
    // kmem_cache_alloc 特有的字段
    unsigned long call_site;           // 分配调用站点（offset 8, size 8）
    const void *ptr;                   // 分配的内存指针（offset 16, size 8）
    size_t bytes_req;                  // 请求分配的字节数（offset 24, size 8）
    size_t bytes_alloc;                // 实际分配的字节数（offset 32, size 8）
    u32 gfp_flags;                   // 内存分配标志（offset 40, size 4）
};

struct kmem_cache_free_event {
    // 通用事件头（所有 tracepoint 共有的字段）
    unsigned long pad;
    // kmem_cache_free 特有的字段
    unsigned long call_site;           // 释放调用站点（offset 8, size 8）
    const void *ptr;                   // 待释放的内存指针（offset 16, size 8）
    char name[4];           // 内存缓存名称的偏移量（offset 24, size 4）
};

// 对应 mm_page_alloc tracepoint 的事件结构体
struct mm_page_alloc_event {
    // 通用事件头（所有 tracepoint 共有的字段）
    unsigned long pad;
    // mm_page_alloc 特有的字段
    unsigned long pfn;                 // 页帧号（offset 8, size 8）
    unsigned int order;                // 分配阶数（offset 16, size 4）
    u32 gfp_flags;                   // 内存分配标志（offset 20, size 4）
    int migratetype;                   // 迁移类型（offset 24, size 4）
};

// 对应 mm_page_free tracepoint 的事件结构体
struct mm_page_free_event {
    // 通用事件头（所有 tracepoint 共有的字段）
   unsigned long pad;
    // mm_page_free 特有的字段
    unsigned long pfn;                 // 页帧号（offset 8, size 8）
    unsigned int order;                // 释放阶数（offset 16, size 4）
};


typedef struct {
    u64 size;
    u64 timestamp_ns;
    u64 pid;
    u32 stack_id;
    u32 type_t;
} event;

typedef struct {
    u64 total_size;
    u64 mem_allocs;
} combined_alloc_info_t;


bpf_map_def SEC("maps") size_record = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

bpf_map_def SEC("maps") alloc_infos = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(size_t),
  .max_entries = 1000000,
};
// 记录当前线程分配的内存总量，如果大于block就上报一次。线程维度存储避免并行导致的一致性问题。
bpf_map_def SEC("maps") thread_alloc_size = {
  .type        = BPF_MAP_TYPE_LRU_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(size_t),
  .max_entries = 10000,
};

bpf_map_def SEC("maps") memptrs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 1000000,
};

static inline __attribute__((__always_inline__)) int alloc_enter(struct pt_regs *ctx, size_t size, u32 type_index) {
    u32 tid = bpf_get_current_pid_tgid();
    u32 memKey = 1;
    SystemConfig *memcfg = bpf_map_lookup_elem(&system_config, &memKey);
    if (memcfg && memcfg->mem_profile_threshold > 0) {
        u64 s = size;
        u64* current_size = bpf_map_lookup_elem(&thread_alloc_size, &tid);
        if (current_size) {
            s += *current_size;
        }
        if (s < memcfg->mem_profile_threshold) {
            bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
            return 0;
        }
        s = 0;
        bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
    }
    u64 key = (u64)type_index << 32 | tid;
    u64 _s = size;
    bpf_map_update_elem(&size_record, &key, &_s, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__)) u64 alloc_exit2(struct pt_regs *ctx, u64 address, u32 type_index) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u64 key = (u64)type_index << 32 | tid;
    u64* size64 = bpf_map_lookup_elem(&size_record, &key);
    if (!size64){
        return 0;
    }

    bpf_map_delete_elem(&size_record, &key);
    if (address == 0){
        return 0;
    }

    u32 pid = id >> 32;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&alloc_infos, &address, size64, BPF_ANY);
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 1, *size64, address);
}

static inline __attribute__((__always_inline__)) int alloc_exit(struct pt_regs *ctx, u32 type_index) {
        return alloc_exit2(ctx, PT_REGS_RC(ctx), type_index);
}

static inline __attribute__((__always_inline__)) u64 free_entry(struct pt_regs *ctx, void *address) {
    u64 addr = (u64)address;
    size_t* s = bpf_map_lookup_elem(&alloc_infos, &addr);
    if (!s)
        return 0;
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    bpf_map_delete_elem(&alloc_infos, &addr);
    u64 ts = bpf_ktime_get_ns();
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 0, *s, addr);
}


SEC("uprobe/malloc")
int malloc_enter(struct pt_regs *ctx) {
    size_t actual_size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, actual_size, MALLOC);
}

SEC("uretprobe/malloc")
int malloc_exit(struct pt_regs *ctx) {
    return alloc_exit2(ctx, PT_REGS_RC(ctx), MALLOC);
}

SEC("uprobe/free")
int free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}

SEC("uprobe/calloc")
int calloc_enter(struct pt_regs *ctx) {
    size_t nmemb = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, nmemb * size, CALLOC);
}
SEC("uretprobe/calloc")
int calloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, CALLOC);
}
SEC("uprobe/realloc")
int realloc_enter(struct pt_regs *ctx) {
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    alloc_enter(ctx, size, REALLOC);
    return free_entry(ctx, ptr);
}

SEC("uretprobe/realloc")
int realloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, REALLOC);
}

SEC("uprobe/mmap")
int mmap_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, MMAP);
}
SEC("uretprobe/mmap")
int mmap_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, MMAP);
}
SEC("uprobe/munmap")
int munmap_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM2(ctx);
    return free_entry(ctx, address);
}

SEC("uprobe/posix_memalign")
int posix_memalign_enter(struct pt_regs *ctx) {
    void ** memptr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u64 memptr64 = (u64)(size_t)memptr;
    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memptrs, &tid, &memptr64,BPF_ANY);
    return alloc_enter(ctx, size, POSIX_MEMALIGN);
}

SEC("uretprobe/posix_memalign")
int posix_memalign_exit(struct pt_regs *ctx) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
    void *addr;
    if (memptr64 == 0)
            return 0;
    bpf_map_delete_elem(&memptrs, &tid);
    if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
            return 0;
    u64 addr64 = (u64)(size_t)addr;
    return alloc_exit2(ctx, addr64, POSIX_MEMALIGN);
}

SEC("uprobe/aligned_alloc")
int aligned_alloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, ALIGNED_ALLOC);
}

SEC("uretprobe/aligned_alloc")
int aligned_alloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, ALIGNED_ALLOC);
}

SEC("uprobe/valloc")
int valloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, size, VALLOC);
}

SEC("uretprobe/valloc")
int valloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, VALLOC);
}

SEC("uprobe/memalign")
int memalign_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, size, MEMALIGN);
}

SEC("uretprobe/memalign")
int memalign_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, MEMALIGN);
}

SEC("uprobe/pvalloc")
int pvalloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, size, PVALLOC);
}

SEC("uretprobe/pvalloc")
int pvalloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, PVALLOC);
}

/** Go **/
// func mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer {
SEC("uprobe/mallocgc_register")
int mallocgc_register_enter(struct pt_regs *ctx) {
    u64 size = (u64)GO_PARM1(ctx);
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u32 pid = id >> 32;
    u64 ts = bpf_ktime_get_ns();
    u32 memKey = 1;
    SystemConfig *memcfg = bpf_map_lookup_elem(&system_config, &memKey);
    if (memcfg && memcfg->mem_profile_threshold > 0) {
        u64 s = size;
        u64* current_size = bpf_map_lookup_elem(&thread_alloc_size, &tid);
        if (current_size) {
            s += *current_size;
        }
        if (s < memcfg->mem_profile_threshold) {
            bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
            return 0;
        }
        s = 0;
        bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
    }
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 1, size, 0);
}

SEC("uprobe/mallocgc_stack")
int mallocgc_stack_enter(struct pt_regs *ctx) {
    u64 size;
    // get first arm from stack
    if (bpf_probe_read_user(&size, sizeof(u64), (void*)((ctx->sp) + 8))) {
        return 0;
    }
    u64 id  = bpf_get_current_pid_tgid();
    u32 tid = id & 0xFFFFFFFF;
    u32 pid = id >> 32;
    u64 ts = bpf_ktime_get_ns();
    u32 memKey = 1;
    SystemConfig *memcfg = bpf_map_lookup_elem(&system_config, &memKey);
    if (memcfg && memcfg->mem_profile_threshold > 0) {
        u64 s = size;
        u64* current_size = bpf_map_lookup_elem(&thread_alloc_size, &tid);
        if (current_size) {
            s += *current_size;
        }
        if (s < memcfg->mem_profile_threshold) {
            bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
            return 0;
        }
        s = 0;
        bpf_map_update_elem(&thread_alloc_size, &tid, &s, BPF_ANY);
    }
    return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, ts, 1, size, 0);
}

/*Python*/
// void * PyObject_Malloc(size_t size)
SEC("uprobe/pyobj_malloc")
int PyObject_Malloc_enter(struct pt_regs *ctx)
{
    size_t nbytes = PT_REGS_PARM1(ctx);
    return alloc_enter(ctx, nbytes, PYMALLOC);
}

// void * PyObject_Malloc(size_t size)
SEC("uretprobe/pyobj_malloc")
int PyObject_Malloc_exit(struct pt_regs *ctx)
{
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYMALLOC);
}

// void * PyObject_Calloc(size_t nelem, size_t elsize)
SEC("uprobe/pyobj_calloc")
int PyObject_Calloc_enter(struct pt_regs *ctx)
{
    size_t nelem = (size_t)PT_REGS_PARM1(ctx);
    size_t elsize = (size_t)PT_REGS_PARM2(ctx);
    return alloc_enter(ctx, nelem * elsize, PYCALLOC);
}

// void * PyObject_Calloc(size_t nelem, size_t elsize)
SEC("uretprobe/pyobj_calloc")
int PyObject_Calloc_exit(struct pt_regs *ctx)
{
    return alloc_exit2(ctx, PT_REGS_RC(ctx), PYCALLOC);
}

// void * PyObject_Realloc(void *ptr, size_t new_size)
// ptr here maybe 0, then cpython will use _PyObject_Malloc
SEC("uprobe/pyobj_realloc")
int PyObject_Realloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    alloc_enter(ctx, size, PYREALLOC);
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, ptr);
}

// void * PyObject_Realloc(void *ptr, size_t new_size)
SEC("uretprobe/pyobj_realloc")
int PyObject_Realloc_exit(struct pt_regs *ctx) {
    return alloc_exit(ctx, PYREALLOC);
}

// void PyObject_Free(void *ptr)
SEC("uprobe/pyobj_free")
int PyObject_Free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return free_entry(ctx, address);
}
