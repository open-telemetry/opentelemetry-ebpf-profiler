Memory Profiling
================

# Meta

- **Author(s)**: Scott Gerring, Erwan Violett, Nicolas Savoire, Nayef Ghattas
- **Start Date**: 2026-07-22
- **Goal End Date**: TBD
- **Primary Reviewers**: [https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers](https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers)

# Abstract

The OTel eBPF profiler today provides on-CPU and [off-CPU profiling](http://design-docs/00001-off-cpu-profiling). One remaining axis for understanding application performance is memory: what drives memory growth, and which call stacks are responsible for it? This document proposes adding **memory profiling** to the profiler as an opt-in feature, attached via USDT (User Statically-Defined Tracepoints) probes that target processes emit on sampled allocations (and, optionally, on the matching frees).

Memory use is contributed to by various mechanisms - code segments, memory mapped files, the stack, and the heap. This proposal focuses on tracking heap allocations, but should provide a robust foundation on which additional memory profiling capabilities can later be built. It is made up of two complementary mechanisms:

1. Allocation profiling - sampling a statistically representative subset of all allocations made in a program
2. Live heap profiling - extends allocation profiling by tracking the corresponding `free`s of all the allocations, allowing the profiler to emit a representation of live memory over time

Efficient memory profiling requires cooperation from the target process. Unlike CPU profiling, where the profiler can sample execution from outside the process, allocation profiling needs a cheap in-process decision about which allocations are worth reporting. The target process therefore provides a small sampling mechanism that emits [USDT](https://www.polarsignals.com/blog/posts/2025/12/10/usdt-deep-dive) events only for a statistically representative subset of allocations, and optionally for the matching frees. The eBPF profiler treats that mechanism as an implementation detail behind a stable, discoverable USDT contract: it discovers the probes at runtime, attaches eBPF uprobes, reuses the existing stack unwinding pipeline, and exports the resulting samples as OTLP profiles while keeping memory telemetry within the profiler's overall export budget.

# Introduction

## Problem

The eBPF profiler already covers two axes of application performance: when threads are on CPU and when they are blocked off CPU, but does not yet give us insight into how memory is being allocated and used (or even leaked!).

Existing per-runtime memory profilers (the JVM, the Go runtime, CPython's `tracemalloc`) only cover *managed* heap. They miss native allocations made directly by the application or, more importantly, by libraries called over the FFI - which for languages like Python is often where a lot of memory cost actually lives. Coarse OS metrics like RSS tell you *that* memory grew, never *who* grew it.

The eBPF profiler is unusually well placed to fill this gap:

- It already captures and symbolises native stacks from outside the process; no in-process unwinder is needed.
- It is cross-language by construction.
- It already runs continuously and per-host, so memory profiling can be delivered for any application via the addition of a small userspace component.

The remaining problems are:

1. The profiler does not currently consume USDT probes at all.
2. It has no eBPF entry points for allocation events, no map for correlating sampled allocations to their frees, and no OTLP output shape for memory data.
3. Allocation events fire at much higher rates than perf samples, so back-pressure must be designed in from the start, and simply hooking 'malloc' and 'free' presents an unreasonably high performance cost for profiled applications.
4. Further to (3), we must ensure that we constrain memory telemetry production in a way that does not allow one process to starve others, and fits within the operational cost model of the full-host profiler (that is, with output telemetry proportional to vCPU on host)

Although our initial focus with this proposal is on *native* heap, this mechanism can be trivially extended to capture managed heap by inserting the USDT probes within the allocation path within the targeted runtime. This would require no additional change on the profiler side.

## Success Criteria

- Memory profiling is **opt-in**:
  - `-allocation-profiling` turns on allocation profiling, attaching the profiler to the allocation side of the USDT contract
  - `-live-heap-profiling` is a further opt-in on top of `-allocation-profiling`, with the free-side eBPF program and uprobe attachment loaded *only* when enabled.
- Live heap tracking has bounded memory usage in the profiler, with both a global cap and a per-process cap, so one pathological or high-allocation process cannot exhaust resources needed to profile other processes.
- Existing stack unwinding code paths are reused; no new unwinder.
- Probes inside libraries `dlopen`'d after process start are eventually picked up.
- Output is standard OTLP profiles using existing sample-type conventions (`alloc_space/bytes`, `alloc_objects/count`, optionally `inuse_space/bytes` and `inuse_objects/count`).
- The feature respects the profiler's existing sample budget; memory events cannot starve on-CPU profiling.
- Compatible with x86-64 and arm64 Linux, maintaining the profiler's existing kernel version requirements.

## Scope

This document focuses on the changes inside `opentelemetry-ebpf-profiler` needed to consume memory USDTs and produce OTLP memory profiles.

### In scope

- The USDT contract the profiler expects from a target process.
- Per-process discovery of `.note.stapsdt` notes and PID-scoped uprobe attachment, with lifecycle management across `dlopen`, exec and exit.
- eBPF entry programs that reuse the existing native unwinder via tail call.
- Heap profiling (alloc-only) and live (in-use) heap profiling (alloc + free), gated by separate CLI flags.
- OTLP output shape (`alloc_space`, `alloc_objects`, and optional `inuse_space` / `inuse_objects`).
- Sample applications and instrumentation on the user-space side and associated performance and implementation observations
- Back-pressure: a closed-loop PID controller on the profiler side that holds memory-event throughput at a configured fraction of the overall sample budget.

### Non-success criteria / out of scope

Everything on the in-process side of the USDT contract:

- How USDTs get into a target process (compile-time wrappers, `LD_PRELOAD`, runtime GOT rewriting).
- Per-architecture deallocation tracking (ARM64 TBI, x86-64 prefix, side-tables).
- Allocator-specific quirks (size classes, alignment).

And from the profiler side, the following are deferred:

- Native memory attribution beyond allocation call stacks, such as classifying memory by runtime component, allocator arena, mapping type, or internal allocator metadata.
- Visualisation and correlation with on-CPU / off-CPU profiles.
- Symbolisation (already handled by the existing pipeline).
- Scaling sampled live-heap bytes against `/proc/<pid>/smaps` so the emitted profile better approximates real process RSS; scaling allocations is a nuanced topic and we believe better tackled on top of a robust foundation as a subsequent step.

# Proposed Solution

## In-process sampler shape

The in-process sampler is out of scope to *design* here, but the profiler's design only makes sense against a rough sketch of what it consumes. The in-process sampler should follow the existing model converged upon by allocators such as [**jemalloc**](https://github.com/jemalloc/jemalloc/blob/dev/doc_internal/PROFILING_INTERNALS.md) and [**tcmalloc**](https://github.com/google/tcmalloc/blob/master/docs/sampling.md):

- **Random interval sampling over allocated bytes**: the sampler draws the byte distance to the next sample from a geometric distribution, or from an exponential approximation, with mean equal to the configured sampling interval (default ~512 KiB of allocated bytes). Equivalently, this models sampled allocations as a Poisson process over allocation volume.
- A **per-thread byte counter** decremented on every allocation; the fast path is a thread-local add and a branch-predicted-taken comparison. When the counter reaches zero a sample fires and a new geometric interval is drawn.
- On a sampled allocation, the sampler emits the `alloc` USDT with a **weight** equal to the unbiased size estimator (`size * interval / (interval - exp(-size/interval) * interval)` in the limit, or more simply `nsamples * interval`). This is what allows the profiler to scale sampled bytes back to true allocation volume without doing the math itself.
- For live-heap profiling, the sampler also tracks which pointers were sampled (mechanism is its own concern - see Out of Scope) and fires the `free` USDT only for those pointers.

We provide an [example implementation for the above contract](https://github.com/DataDog/libdatadog/tree/main/libdd-profiling-heap-sampler), with the intention of validating the eBPF profiler-side implementation.

The profiler does not care which allocator is wrapped, which language the process is written in, or how the USDTs were injected; only that the contract below holds and that allocations are sampled according to the description above.

## USDT contract

The profiler expects a target process to emit the following USDTs from a single provider:

| Probe | Args | When fired | Scope |
| :---- | :---- | :---- | :---- |
| `otel_memory:alloc(user, size, w)` | `user` = user-visible pointer, `size` = bytes, `w` = unbiased weight | On a **sampled** allocation | Initial release |
| `otel_memory:free(ptr)` | `ptr` = pointer being freed | On free of a previously-sampled allocation | Initial release |
| `otel_memory:mmap(address, size)` | `addr` = mapped region start pointer, `size` = mapped region size in bytes | On successful `mmap` | Subsequent work; build on top of lessons from the initial release |
| `otel_memory:munmap(address, size)` | `addr` = unmapped region start pointer, `size` = unmapped region size in bytes | On successful `munmap` | Subsequent work; build on top of lessons from the initial release |

`weight` is the unbiased size estimator (`nsamples * sampling_interval`) already produced by the in-process sampler. The profiler uses it directly as the value for `alloc_space` samples; it does not need to know how the sampler computed it. Note that these USDT signatures generalise across all allocator paths - `malloc`, `cmalloc`, `aligned_alloc`, etc.

For the initial support in the profiler we plan to support `alloc` and `free` only and add `mmap` support subsequently as this is more nuanced.

The profiler does **not** care how these USDTs got into the process. Compile-time wrappers, `LD_PRELOAD`, runtime GOT injection - all are equivalent from this side.

## Expected Runtime Cost in Userspace

Although we do not intend to specify the userspace side of the USDT in this document, we have considered the cost of the mechanism described above for both the fast (i.e. unsampled, fired on every allocation) and slow cases when implemented idiomatically.

On each allocation, the sampler resolves thread-local state, updates a per-thread byte counter, and checks whether the sampling threshold has been crossed. In the common case it has not, so the allocation returns unsampled after only TLS access, integer arithmetic, and a well-predicted branch. Only when the counter crosses the threshold does execution jump to the slow path, where the sampler draws a new interval and records the allocation as sampled.

Experimentally the overhead of this on unsampled allocations adds single digit nanoseconds. When nothing is attached to the USDT, it exists as a `NOP` adding no additional cost.

## USDT discovery

USDT notes are emitted into `.note.stapsdt` ELF sections. For each process the profiler tracks, we scan the executable file-backed mappings, parse their `.note.stapsdt` section, filter to our provider, and translate probe names to a small fixed `ProbeKind` enum (`ProbeHeapAlloc`, `ProbeHeapFree`).

Parsing is delegated to [`github.com/parca-dev/usdt`](http://github.com/parca-dev/usdt). This avoids hand-rolling SystemTap SDT note parsing while keeping the existing `cilium/ebpf` runtime for attachment - we get the parser without adopting a second eBPF stack. This Polar Signals library is already being used successfully in Polar Signals' downstream fork of the full-host profiler and would benefit the community to be upstreamed to support this work.

Parse results are cached by `OnDiskFileIdentifier`, so a `.so` mapped by many processes is parsed once. Probe-less binaries are also cached (empty result) to avoid re-scanning on every reconcile.

## Per-process attachment and lifecycle

Uprobes are attached **per-PID** using cilium/ebpf's `UprobeOptions.PID`, not globally per binary. Memory profiling is a per-process decision and PID-scoped links fit the existing `ProcessManager` lifecycle.

A new `usdt.Manager` owns the global parse cache and the BPF programs; a per-PID `usdt.Instance` owns that PID's live `link.Link` attachments, keyed by `(PID, FileID, Kind, Offset)`.

Reconciliation runs on **every** `ProcessManager.SynchronizeProcess` call (not only on first sight of a PID), diffing the set of expected probes against the set currently attached for the PID. This is what catches `.so`s that were `dlopen`'d after the process started — the most important case in practice for Python workloads.

Detach happens in `processPIDExit` alongside the existing interpreter teardown.

## eBPF entry programs

Two new eBPF programs, `uprobe_heap_alloc` and `uprobe_heap_free`, live in `support/ebpf/heap_usdt.ebpf.c`. They:

1. Read USDT arguments out of `pt_regs` using a small arch-specific helper (`usdt_arg0/1/2` for x86-64 and arm64).
2. Tail-call into the existing native unwinder via `collect_trace`, tagging the trace with a new origin (`TRACE_HEAP_ALLOC`) and passing `weight` through as the trace value. This is the same shape used by the off-CPU entry program.
3. For free: short-circuit if `(pid, ptr)` is not in our sampled allocation correlation map. This keeps the hot path cheap.

The `uprobe_heap_free` program is loaded into the kernel only when `-live-heap-profiling` is enabled. When only `-heap-profiling` is on, the program isn't loaded and the `free` USDT isn't attached, so plain allocation profiling pays only the alloc-side cost.

## Reporting / OTLP shape

Two sibling profiles share the alloc call stacks and timestamps:

- `sample_type = alloc_space/bytes` - values are USDT `weight`.
- `sample_type = alloc_objects/count` - value is `1` per event; aggregation gives the number of allocation events captured.

When live-heap profiling is enabled, the free program decrements the correlated allocation's contribution; we additionally emit:

- `sample_type = inuse_space/bytes`
- `sample_type = inuse_objects/count`

These four sample types follow standard pprof / OTLP profile conventions.

## Back-pressure

Allocation USDTs are expected to fire more frequently than perf samples even after in-process sampling. Back-pressure is layered at two points:

- **In-process: open-loop random-interval sampling.** The in-process side draws the next byte distance to a sample from a geometric distribution, or an exponential approximation, with mean equal to the configured sampling interval per thread. This is open-loop - the application has no idea what the profiler is currently doing - and gives an unbiased estimator via `weight`. Cheap, simple, and the primary cost of the book-keeping is accessing the TLS to track state. This is also the approach used by samplers such as jemalloc and tcmalloc in their own observability infrastructure; by supporting the ecosystem where it is, we increase the chances of being able to influence allocators to include sampling hooks by default when this method shows adoption.
- **eBPF / collector side: closed-loop PID control.** The profiler maintains a target rate of memory events (expressed as a fraction of the overall sample budget) and runs a PID controller in user space that adjusts a drop probability applied inside the `uprobe_heap_alloc` eBPF program. The controller observes the measured event rate, compares it against the target, and updates the threshold so that memory events occupy a bounded share of the payload regardless of workload spikes.

Notes on the controller:

- The controlled variable is a per-CPU drop threshold read by the eBPF program at the top of `uprobe_heap_alloc`; the eBPF side does one compare-and-bail.
- The setpoint is `target_memory_events_per_sec`, derived from the existing sample budget multiplied by a configurable memory fraction. Memory events cannot starve on-CPU profiling because the budget is apportioned, not shared.
- Dropped events are still counted (so we can surface drop ratios as a metric and ultimately fold the drop probability back into `weight` for unbiased totals).
- The controller's tuning constants and the target memory fraction are to be determined empirically; see Plan to Acquire Missing Data.
- The controller bounds memory-event throughput, but it does not by itself bound the amount of live allocation state retained for `inuse_*` profiles. Live heap tracking therefore also requires explicit global and per-process state limits, described in the live heap state bounds section.

In combination: the in-process interval sampler bounds the event rate the application can produce, and the PID controller bounds what actually reaches the profile under load. The two layers do not need to agree - the in-process sampler is unaware of the controller, which is what keeps the hot path branch-prediction-friendly and allocator-agnostic.

It is foreseeable that more advanced allocator implementations may choose to use a PID or similar mechanism also. Assuming weights are summed correctly to account for this, the profiler requires no awareness of the particular sampling mechanism and the application would simply benefit from a decreased impact of context switching when profiling is active.

# Alternatives Considered

- Attach to kernel tracepoints **`sys_enter_brk`** / **`sys_enter_mmap`** /etc. Too far from application allocation patterns: modern allocators go to great lengths to avoid kernel calls, so most allocations are invisible at this layer. Down the road, this might be useful to help us catch `mmap`s that do not go through libc.
- **Upstream USDTs into common allocators (`jemalloc`, `tcmalloc`, `glibc`) so that users do not need to change their applications** - ultimately it would be convenient for upstream allocators to contain the USDTs directly and we hope in the long run we can use adoption by the OpenTelemetry community to incentivise this. In the meantime, we have begun looking at using the upstream sampling APIs directly, for instance [extending the Rust jemalloc crate](https://github.com/tikv/jemallocator/pull/172) so we can build on top of it.
- **Attach uprobes to allocator-specific internal sampling paths (`jemalloc`, `tcmalloc`)** - we discount this approach as it is fragile against the internals of the allocators, the allocators do not by default have sampling turned on (or if it is turned on, it may do more work than we want - for instance, with jemalloc and its optional stack-collection behaviour in the sampling path), and does not generalise to all allocators.
- **Sample every alloc/free.** Prohibitive overhead; allocators are on the critical path for most workloads.
- **Global (per-binary) uprobe attachment** rather than per-PID. Loses the ability to opt processes in/out individually and complicates cleanup; doesn't fit the profiler's existing lifecycle model.
- **Hand-rolled `.note.stapsdt` parsing.** Pointless given the `parca-dev/usdt` parser already exists, is small, and is permissively licensed.

## Author's Preferred Solution

The proposal above is the preferred design. The two non-obvious calls are:

- **Treating the in-process sampler as an external contract** rather than bundling it. This keeps the upstream surface area small and lets multiple in-process implementations (a Rust `GlobalAlloc` wrapper, a runtime-injected `.so`, an upstream jemalloc patch in future) all target the same profiler.
- **Gating the free path behind a separate flag.** Allocation profiling is enormously useful on its own, and free-side machinery is the only part that needs a correlation map and pays cost on every free of a sampled pointer. Splitting the flags lets users opt into the cheaper mode.

# Testing Strategy

## Testing of Proposed Solution Itself

- **Unit tests** for: USDT note parser adapter, provider/probe-name filtering, the reconcile diff (probes added on `dlopen`, removed on `munmap`/exit).
- **Integration tests** using small Rust and C test binaries that emit the contract USDTs with deterministic allocation/free patterns; assert OTLP output shape, value sums, and sample counts. A PoC of this kind already exists on the `sgg/heap-prof-poc` branch[^1] and can be cleaned up into the upstream test suite.
- **Lifecycle coverage** for fork, exec, `dlopen`-after-start, exit, short-lived processes.
- **Negative tests**: process without our USDTs (nothing attaches); process with USDTs but `-heap-profiling` not set (nothing attaches); `-live-heap-profiling` without `-heap-profiling` (rejected at flag parse).

## Impact on Testing of Other Systems/Components

The memory pipeline is an additive code path: the on-CPU and off-CPU flows are unaffected when the feature flags are off. The `usdt.Manager` is injected into `ProcessManager` and is nilable, so existing `ProcessManager` tests continue to work without modification.

# Plan to Acquire Missing Data

- Final provider name. Currently `otel_memory` - we should agree on the formal, upstream name.
- **Argument-descriptor handling.** v1 reads `pt_regs` directly, assuming the SysV ABI. We need to confirm whether any of the in-process samplers we expect to support emit non-trivial SDT argument descriptors that require per-arg location decoding.
- **`mmap` / `munmap` probes.** Pending the reference sampler adding them; once available, they slot into the same `ProbeKind` enum and reuse the same entry-program pattern.
- **Empirical overhead.** Benchmarks of plain heap profiling vs live-heap profiling on representative Rust and Python workloads, with the existing on-CPU profiler running, to size the memory share of the sample budget.
- **PID controller tuning.** Setpoint (target memory-events / sec, or equivalently target fraction of the sample budget), proportional / integral / derivative gains, and sample window. We should look at the JVM's TLAB allocation sampler as a starting point and tune against the same benchmark workloads used for overhead measurement.
- **Live heap state sizing.** Determine the default global and per-process caps for sampled-allocation live-state tracking.

# Decision

TBD. To be filled in once the proposal has been reviewed.

[^1]: PoC branch demonstrating the end-to-end pipeline against the reference sampler: `sgg/heap-prof-poc` on this repo.
