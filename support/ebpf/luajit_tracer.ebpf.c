// This file contains the code and map definitions for the LuaJIT tracer

#include "bpfdefs.h"
#include "errors.h"
#include "tracemgmt.h"
#include "types.h"

struct luajit_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, LuaJITProcInfo);
  __uint(max_entries, 1024);
} luajit_procs SEC(".maps");

// Unimplemented; just a stub that compiles and references the map.
static EBPF_INLINE int unwind_luajit([[maybe_unused]] struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  u32 pid              = record->trace.pid;
  LuaJITProcInfo *info = bpf_map_lookup_elem(&luajit_procs, &pid);
  if (!info) {
    DEBUG_PRINT("lj: no LuaJIT introspection data");
    increment_metric(metricID_UnwindLuaJITErrNoProcInfo);
    goto exit;
  }
  increment_metric(metricID_UnwindLuaJITAttempts);

exit:
  return -1;
}
MULTI_USE_FUNC(unwind_luajit)
