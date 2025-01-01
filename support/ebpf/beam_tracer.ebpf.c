#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

bpf_map_def SEC("maps") beam_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(BEAMProcInfo),
  .max_entries = 1024,
};

SEC("perf_event/unwind_beam")
int unwind_beam(struct pt_regs *ctx) {
  static const char fmt[] = "Unwinding BEAM stack";
  bpf_trace_printk(fmt, sizeof(fmt));
  DEBUG_PRINT("Unwinding BEAM stack");

  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    return -1;
  }

  int unwinder = get_next_unwinder_after_interpreter(record);
  u32 pid = record->trace.pid;

  BEAMProcInfo *beaminfo = bpf_map_lookup_elem(&beam_procs, &pid);
  if (!beaminfo) {
    DEBUG_PRINT("No BEAM introspection data");
    goto exit;
  }

  DEBUG_PRINT("==== unwind_beam stack_len: %d, pid: %d ====", record->trace.stack_len, record->trace.pid);

exit:
  tail_call(ctx, unwinder);
  return -1;
}
