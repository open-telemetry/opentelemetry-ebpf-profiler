// Minimal CUPTI activity buffer definitions for BPF programs.
// Stripped-down version of CUpti_ActivityKernel5 with exact layout
// matching the CUDA 12.x CUPTI headers (sizeof = 160, aligned 8).
//
// Only the fields needed by BPF are named; the rest are padding.
// Field offsets verified against the real struct with offsetof().

#ifndef OPTI_CUPTI_ACTIVITY_BPF_H
#define OPTI_CUPTI_ACTIVITY_BPF_H

// CUpti_ActivityKind values we care about
#define CUPTI_ACTIVITY_KIND_KERNEL            3
#define CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL 10

// Matches the layout of CUpti_ActivityKernel5 exactly.
// Explicit padding replaces __packed__ to avoid unnecessary unaligned-access
// handling in BPF.  The struct uses aligned(8) and a static size assert.
struct cupti_activity_kernel5 {
  u32 kind;            // offset 0   - CUpti_ActivityKind
  u8 _pad1[12];        // offset 4   - cacheConfig, sharedMemConfig,
                       //              registersPerThread,
                       //              partitionedGlobalCache x2
  u64 start;           // offset 16  - kernel start timestamp (ns)
  u64 end;             // offset 24  - kernel end timestamp (ns)
  u64 completed;       // offset 32  - completion timestamp
  u32 device_id;       // offset 40
  u32 context_id;      // offset 44
  u32 stream_id;       // offset 48
  u8 _pad2[40];        // offset 52  - gridX/Y/Z, blockX/Y/Z,
                       //              staticSharedMemory,
                       //              dynamicSharedMemory,
                       //              localMemoryPerThread,
                       //              localMemoryTotal
  u32 correlation_id;  // offset 92
  s64 grid_id;         // offset 96
  u64 name_ptr;        // offset 104 - const char* (user-space pointer)
  u64 _reserved0;      // offset 112
  u64 queued;          // offset 120
  u64 submitted;       // offset 128
  u8 _pad3[8];         // offset 136 - launchType, isSharedMemoryCarveout,
                       //              sharedMemoryCarveoutRequested,
                       //              padding, sharedMemoryExecuted
  u64 graph_node_id;   // offset 144
  u32 shmem_limit_cfg; // offset 152 - CUpti_FuncShmemLimitConfig
  u32 graph_id;        // offset 156
} __attribute__((aligned(8)));

// Verify expected size at compile time
_Static_assert(
  sizeof(struct cupti_activity_kernel5) == 160, "cupti_activity_kernel5 size mismatch");

#endif // OPTI_CUPTI_ACTIVITY_BPF_H
