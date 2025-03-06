// References to the map definitions in the BPF C code.

#ifndef OPTI_EXTMAPS_H
#define OPTI_EXTMAPS_H

#include "bpf_map.h"

// References to map definitions in *.ebpf.c.
extern bpf_map_def perf_progs;
extern bpf_map_def per_cpu_records;
extern bpf_map_def kernel_stackmap;
extern bpf_map_def pid_page_to_mapping_info;
extern bpf_map_def metrics;
extern bpf_map_def report_events;
extern bpf_map_def reported_pids;
extern bpf_map_def pid_events;
extern bpf_map_def inhibit_events;
extern bpf_map_def interpreter_offsets;
extern bpf_map_def system_config;
extern bpf_map_def trace_events;
extern bpf_map_def go_procs;

#if defined(TESTING_COREDUMP)

// References to maps in alphabetical order that
// are needed only for testing.

extern bpf_map_def apm_int_procs;
extern bpf_map_def exe_id_to_8_stack_deltas;
extern bpf_map_def exe_id_to_9_stack_deltas;
extern bpf_map_def exe_id_to_10_stack_deltas;
extern bpf_map_def exe_id_to_11_stack_deltas;
extern bpf_map_def exe_id_to_12_stack_deltas;
extern bpf_map_def exe_id_to_13_stack_deltas;
extern bpf_map_def exe_id_to_14_stack_deltas;
extern bpf_map_def exe_id_to_15_stack_deltas;
extern bpf_map_def exe_id_to_16_stack_deltas;
extern bpf_map_def exe_id_to_17_stack_deltas;
extern bpf_map_def exe_id_to_18_stack_deltas;
extern bpf_map_def exe_id_to_19_stack_deltas;
extern bpf_map_def exe_id_to_20_stack_deltas;
extern bpf_map_def exe_id_to_21_stack_deltas;
extern bpf_map_def exe_id_to_22_stack_deltas;
extern bpf_map_def exe_id_to_23_stack_deltas;
extern bpf_map_def hotspot_procs;
extern bpf_map_def dotnet_procs;
extern bpf_map_def perl_procs;
extern bpf_map_def php_procs;
extern bpf_map_def py_procs;
extern bpf_map_def ruby_procs;
extern bpf_map_def stack_delta_page_to_info;
extern bpf_map_def unwind_info_array;
extern bpf_map_def v8_procs;
extern bpf_map_def luajit_procs;

#endif // TESTING_COREDUMP

#endif // OPTI_EXTMAPS_H
