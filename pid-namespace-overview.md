# PID Namespace & ProcFS Problem/Solution Matrix

## Overview of Deployment Scenarios

PRs / branches
  - rogercoll: https://github.com/rogercoll/opentelemetry-ebpf-profiler/tree/parametrize_proc_fs_rebase
  - shivanshuraj: https://github.com/shivanshuraj1333/opentelemetry-ebpf-profiler/tree/feat/nested-pid-namespace-translation
  - simonepri: https://github.com/simonepri/opentelemetry-ebpf-profiler/tree/fix/descendant-pid-namespace-translation

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                        PROFILER PID NAMESPACE POSITION                                      │
├──────────────────────────────┬───────────────────────┬──────────────────────────────────────┤
│        HOST / INITIAL        │     NESTED (DEEPER)   │         ARBITRARY CONTAINER          │
│      (RootFs == "/")         │   (RootFs != "/")     │      (Custom /proc mount path)       │
│                              │                       │                                      │
│  ┌───────────────────────┐   │  ┌─────────────────┐  │  ┌────────────────────────────────┐  │
│  │ simonepri: Profiler   │   │  │ shivanshuraj:   │  │  │ rogercoll: Profiler in         │  │
│  │ here, targets in      │   │  │ Profiler here,  │  │  │ container, host /proc at       │  │
│  │ descendant namespaces │   │  │ eBPF reports    │  │  │ custom path (RootFs != "/")    │  │
│  └───────────────────────┘   │  │ kernel-root PIDs│  │  │                                │  │
│                              │  └─────────────────┘  │  └────────────────────────────────┘  │
└──────────────────────────────┴───────────────────────┴──────────────────────────────────────┘
```

---

## Matrix: Problems, Existing Solutions, and Branch Coverage

| # | Problem | Deployment Scenario | Existing Solution (upstream/main) | `simonepri/fix/descendant-pid-namespace-translation` | `shivanshuraj1333/feat/nested-pid-namespace-translation` | `rogercoll/parametrize_proc_fs_rebase` |
|---|---------|---------------------|-----------------------------------|------------------------------------------------------|--------------------------------------------------------|----------------------------------------|
| **1** | **eBPF reports PIDs from kernel-root namespace, but profiler's `/proc` view is in a nested PID namespace** | Profiler in nested PID namespace (kind/minikube DaemonSet, `hostPID: false`) | ❌ None — PIDs mismatch, process lookup fails | ❌ Doesn't address (assumes profiler in parent ns) | ✅ **Solves**: Discovers profiler's pidns level at runtime via `read_pid_level` probe; translates kernel-root → profiler ns | ⚠️ **Partial**: Discovers host PID via `BPF_PROG_TEST_RUN`; uses `RootFs` to access host `/proc` |
| **2** | **Profiler in host/parent PID namespace, targets in descendant/child PID namespaces (sidecar)** | Sidecar profiler in host pidns, targets in container pidns (`hostPID: true`) | ⚠️ `PIDNamespaceTranslation=true` (exact match only via `bpf_get_ns_current_pid_tgid`) | ✅ **Solves**: Walks task's `struct pid` hierarchy to find PID in target ns; supports `auto`/`exact`/`descendants` modes | ❌ Doesn't address (assumes profiler in nested ns) | ❌ Doesn't address |
| **3** | **Profiler in container with custom `/proc` mount path (`RootFs != "/"`), needs to read target process memory & metadata** | Profiler containerized, host `/proc` mounted at `/host/proc` or similar | ❌ Hardcoded `/proc/<pid>/` paths everywhere | ❌ Doesn't address | ❌ Doesn't address | ✅ **Solves**: Refactors `Process` abstraction with `rootFsPath`; all `/proc` access via `RootFs` config; `process_vm_readv` works via `rootFsPath` |
| **4** | **Profiler in container (own PID namespace), `os.Getpid()` returns container PID but eBPF `bpf_get_current_pid_tgid()` returns host TGID** | Profiler containerized without `hostPID: true` | ❌ Analysis probes filter by `os.Getpid()` — never match | ❌ Doesn't address | ❌ Doesn't address | ✅ **Solves**: `loadSelfHostNamespacePID()` runs BPF test-run to get host TGID; uses it for analysis probe filtering |
| **5** | **Kernel symbolization (`kallsyms`) needs host `/proc/kallsyms` when profiler in container** | Profiler in container, host `/proc` at custom path | ❌ Hardcoded `/proc/kallsyms` | ❌ Doesn't address | ❌ Doesn't address | ✅ **Solves**: `kallsyms.NewSymbolizer(cfg.RootFs)` reads from `RootFs/proc/kallsyms` |
| **6** | **Container ID extraction from `/proc/<pid>/cgroup` needs correct procfs path** | Any containerized profiler | ❌ Hardcoded `/proc/<pid>/cgroup` | ❌ Doesn't address | ❌ Doesn't address | ✅ **Solves**: `process.extractContainerID()` uses `procBase` derived from `rootFsPath` |
| **7** | **Remote memory access (`process_vm_readv`) needs correct PID when profiler in different pidns** | Profiler in container, target in host or another container | ❌ Uses `os.Getpid()` directly | ❌ Doesn't address | ❌ Doesn't address | ✅ **Solves**: `GetRemoteMemory()` now takes `rootFsPath`; PID is translated appropriately |
| **8** | **Auto-detection: enable translation only when actually needed (nested ns detected)** | All scenarios | ❌ Manual `PIDNamespaceTranslation=true/false` | ✅ **Auto mode**: Tries BTF layout parse; falls back to exact if unavailable | ✅ **Auto mode (string)**: "auto" = enable when nested ns detected via `read_pid_level` > 0 | ⚠️ **Implicit**: Enabled when `RootFs != "/"` (assumes container = nested pidns) |
| **9** | **Integration test coverage for PID namespace translation** | Validation | ❌ None | ✅ **Full test**: Creates real descendant pidns with `CLONE_NEWPID`; verifies translated PIDs work with `/proc` | ❌ No new integration tests | ⚠️ Adds `systemconfig_integration_test.go` for BTF parsing, but no pidns-specific test |
| **10** | **eBPF binary size impact** | Production deployment | Baseline | +56 KB (amd64) — extra walk logic & rodata vars | +18 KB (amd64) — simpler single-index walk | ~0 KB (refactoring only, no new eBPF logic for translation) |

---

## Detailed Comparison of the Three Branches

| Dimension | `simonepri` (Descendant) | `shivanshuraj1333` (Nested) | `rogercoll` (Parametrize ProcFS) |
|-----------|---------------------------|----------------------------|----------------------------------|
| **Primary Problem** | Profiler in parent ns, targets in child ns | Profiler in nested ns, eBPF reports kernel-root PIDs | Profiler in container, host `/proc` at custom path |
| **Translation Direction** | Child ns → Parent ns | Kernel-root ns → Profiler ns | N/A (userspace path resolution) |
| **eBPF Mechanism** | `bpf_get_ns_current_pid_tgid()` + manual `struct pid` walk | Manual walk from `task_struct.thread_pid` using discovered `profiler_pidns_level` | `BPF_PROG_TEST_RUN` on `raw_tracepoint` to get host TGID |
| **Namespace Discovery** | Target ns inode known at config time (`/proc/self/ns/pid`) | Profiler's own ns level discovered at runtime via BPF probe | `RootFs != "/"` implies containerized; host PID via test-run |
| **Config API** | Typed enum: `PIDNamespaceTranslationMode {Auto, Exact, Descendants}` | String: `PIDNamespaceTranslation {"off","on","auto"}` | String: `RootFs` path (default "/") |
| **Fallback Behavior** | Auto → Exact if BTF unavailable | Auto → kernel-root PIDs if BTF unavailable / old kernel | No translation; uses `RootFs` for all `/proc` access |
| **Analysis Probes Fixed** | No (uses existing `pid_ns_translation_enabled`) | Yes — `is_our_analysis_task()` now uses translated PID | Yes — `loadSelfHostNamespacePID()` gets host TGID for filtering |
| **Max Nesting Depth** | 33 (kernel `PID_NAMESPACE_MAX_LEVELS`) | 8 (hardcoded `MAX_PID_NS_LEVELS`) | N/A (userspace) |
| **ProcFS Access** | Unchanged (assumes host `/proc`) | Unchanged (assumes host `/proc`) | **Fully parametrized** — all `/proc` access via `RootFs` |
| **Key Files Changed** | `tracemgmt.h`, `native_stack_trace.ebpf.c`, `systemconfig.go`, `tracer.go`, integration test | `bpfdefs.h`, `native_stack_trace.ebpf.c`, `system_config.ebpf.c`, `systemconfig.go`, `tracer.go` | `process.go`, `types.go`, `systemconfig.go`, `tracer.go`, `remotememory_linux.go`, `kallsyms.go`, `tracer_pid.ebpf.c` |

---

## Gap Analysis: What's Still Missing for Full Coverage

| Gap | Required Combination | Notes |
|-----|---------------------|-------|
| **Profiler in nested ns + targets in deeper descendant ns** | shivanshuraj + simonepri | Need to walk from profiler's level down to target's level |
| **Profiler in container (custom RootFs) + targets in descendant ns** | rogercoll + simonepri | Need both custom `/proc` paths AND descendant translation |
| **Profiler in nested ns (kind) + custom RootFs mount** | shivanshuraj + rogercoll | Both apply to kind/minikube DaemonSet |
| **Unified config API** | All three | Enum vs string inconsistency; `RootFs` vs `PIDNamespaceTranslationMode` |
| **Single auto-detection logic** | All three | Three different "auto" implementations |
| **Comprehensive test matrix** | All three | Need tests covering all 3×3 scenario combinations |

---

## Recommended Unified Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNIFIED PID TRANSLATION LAYER                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. STARTUP DISCOVERY (from rogercoll + shivanshuraj)                   │
│     ├─ Read RootFs config (default "/")                                 │
│     ├─ If RootFs != "/": run BPF test-run → get host TGID               │
│     ├─ Run read_pid_level probe → get profiler_pidns_level              │
│     └─ Read target_pid_ns_inode from /proc/self/ns/pid (or RootFs)      │
│                                                                         │
│  2. TRANSLATION STRATEGY (unifies simonepri + shivanshuraj)             │
│     ├─ Task in profiler's exact pidns: bpf_get_ns_current_pid_tgid( )   │
│     ├─ Task in descendant of profiler: walk pid→numbers[level]          │
│     ├─ Task in ancestor of profiler: walk up via ns.inum match          │
│     └─ Task in unrelated ns: return 0 (filter out)                      │
│                                                                         │
│  3. USERSPACE PROCFS ACCESS (from rogercoll)                            │
│     └─ All /proc/<pid>/ access via RootFs parameter                     │
│                                                                         │
│  4. CONFIG API                                                          │
│     ├─ RootFs: string (default "/")                                     │
│     ├─ PIDNamespaceTranslation: Mode {Off, Exact, Descendants, Auto}    │
│     └─ Auto = (RootFs != "/" || profiler_pidns_level > 0)               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Priority Recommendation

| Priority | Branch to Merge First | Rationale |
|----------|----------------------|-----------|
| **1** | `rogercoll/parametrize_proc_fs_rebase` | Foundational refactor — enables all containerized deployments; fixes analysis probes; prerequisite for others |
| **2** | `shivanshuraj1333/feat/nested-pid-namespace-translation` | Solves most common production issue (kind/minikube DaemonSet); smaller eBPF change |
| **3** | `simonepri/fix/descendant-pid-namespace-translation` | More general but narrower use case (sidecar); larger eBPF change; needs integration with unified discovery |

The **ideal end state** merges all three with a unified translation layer that handles:
- Profiler at **any** pidns level (discovered at startup)
- Targets at **any** pidns level (walked at sample time)
- ProcFS at **any** mount path (configured via `RootFs`)