Memory Profiling
================

# Meta

- **Author(s)**: Scott Gerring, Erwan Violett, Nicolas Savoire, Nayef Ghattas
- **Start Date**: 2026-07-22
- **Goal End Date**: TBD
- **Primary Reviewers**: [https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers](https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers)

# Abstract

This document proposes adding memory profiling to the OTel eBPF profiler as an opt-in feature. Target processes emit USDT probes on sampled heap allocations (and optionally on the matching frees); the profiler discovers these probes, attaches per-PID uprobes, reuses the existing native unwinder, and exports the results as standard OTLP profiles. Two complementary modes are proposed: **allocation profiling** (which call stacks are allocating) and **live heap profiling** (which allocations are still alive), gated by separate flags.

# Introduction

## Problem

The eBPF profiler already covers two axes of application performance: when threads are on CPU and when they are blocked off CPU, but does not yet give us insight into how memory is being allocated and used (or even leaked!).

Process memory usage is driven by many mechanisms - code segments, memory-mapped files, the stack, and the heap - but heap allocations are both the most dynamic and the least visible today, so they are the focus of this proposal.

Existing per-runtime memory profilers (the JVM, the Go runtime, CPython's `tracemalloc`) only cover *managed* heap. They miss native allocations made directly by the application or by libraries called over the FFI - which for languages like Python is often where a lot of memory cost actually lives. Coarse OS metrics like RSS tell you that memory grew, never who grew it.

The eBPF profiler is well placed to fill this gap:

- It already captures and symbolises stacks from outside the process; no in-process unwinder is needed.
- It is cross-language by construction.
- It already runs continuously and per-host, so memory profiling can be delivered for any application via the addition of a small userspace component.

The remaining problems are:

1. The profiler does not currently consume USDT probes at all.
2. It has no eBPF entry points for allocation events, no map for correlating sampled allocations to their frees, and no OTLP output shape for memory data.
3. Allocation events fire at much higher rates than perf samples, so back-pressure must be designed in from the start, and simply hooking 'malloc' and 'free' presents an unreasonably high performance cost for profiled applications.
4. Further to the back-pressure problem above, we must ensure that we constrain memory telemetry production in a way that does not allow one process to starve others, and fits within the operational cost model of the full-host profiler (that is, with output telemetry proportional to vCPU on host)
5. Attaching uprobes directly to allocator internals is impractical for several reasons: allocators may be statically linked, making symbols invisible to the profiler; allocator-internal sampling paths are typically compiled out or disabled by default, leaving only the hot allocation entry points which fire too frequently to hook without unacceptable cost (see (3)); and internal symbol names are a moving target across allocator versions. This motivates a contract-based approach where the target process explicitly provides the probes.

Although our initial focus with this proposal is on *native* heap, this mechanism can be trivially extended to capture managed heap by inserting the USDT probes within the allocation path within the targeted runtime. This would require no additional change on the profiler side.

## Success Criteria

- Memory profiling is **opt-in**:
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
- Heap profiling (alloc-only) and live (in-use) heap profiling (alloc + free), if configured accordingly.
- OTLP output shape (`alloc_space`, `alloc_objects`, and optional `inuse_space` / `inuse_objects`).
- Sample applications and instrumentation on the user-space side and associated performance and implementation observations
- Back-pressure: a closed-loop PID controller on the profiler side that holds memory-event throughput at a configured fraction of the overall sample budget.

### Non-success criteria / out of scope

Everything on the in-process side of the USDT contract:

- How USDTs get into a target process (compile-time wrappers, `LD_PRELOAD`, runtime GOT rewriting). See **Producing the USDTs in userspace** for the delivery models we've considered; ultimately we want to focus on providing a _uniform_ mechanism for tracking allocations, regardless of how and where the probes are fired.
- Allocator-specific quirks (size classes, alignment).

And from the profiler side, the following are deferred:

- Native memory attribution beyond allocation call stacks, such as classifying memory by runtime component, allocator arena, mapping type, or internal allocator metadata.
- Visualisation and correlation with on-CPU / off-CPU profiles.
- Symbolisation (already handled by the existing pipeline).
- Scaling sampled live-heap bytes against `/proc/<pid>/smaps` so the emitted profile better approximates real process RSS; scaling allocations is a nuanced topic and we believe better tackled on top of a robust foundation as a subsequent step.

# Proposed Solution

This design builds on Florian's Probes API ([open-telemetry/opentelemetry-ebpf-profiler#1658](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/1658)), which shapes the implementation throughout: memory profiling is implemented as just another probe type within it, rather than a bespoke subsystem. We anticipate needing to extend that API with dynamic per-process registration and de-registration, to fit the reconciliation model described in Per-process attachment and lifecycle.

## USDT contract

The profiler expects a target process to emit the following USDTs from a single provider:

| Probe | Args | When fired | Scope |
| :---- | :---- | :---- | :---- |
| `otel_memory:alloc(user, size, w)` | `user` = user-visible pointer, `size` = bytes, `w` = unbiased weight | On a **sampled** allocation | Initial release |
| `otel_memory:free(ptr)` | `ptr` = pointer being freed | On free of a previously-sampled allocation | Initial release |
| `otel_memory:mmap(address, size)` | `address` = mapped region start pointer, `size` = mapped region size in bytes | On successful `mmap` | Subsequent work; build on top of lessons from the initial release |
| `otel_memory:munmap(address, size)` | `address` = unmapped region start pointer, `size` = unmapped region size in bytes | On successful `munmap` | Subsequent work; build on top of lessons from the initial release |

`weight` is `nsamples * sampling_interval`, already computed by the in-process sampler (see **Background** below for the sampling algorithm). `nsamples` counts the number of sampling-interval boundaries the allocation's byte range crossed: 1 for a typical allocation, more for a single allocation large enough to span several intervals. The profiler uses `weight` directly as the value for `alloc_space` samples; it does not need to know how the sampler computed it. Note that these USDT signatures generalise across all allocator paths - `malloc`, `cmalloc`, `aligned_alloc`, etc.

For the initial support in the profiler we plan to support `alloc` and `free` only and add `mmap` support subsequently as this is more nuanced.

We don't version the contract explicitly (no version field on the provider or probe names). We think it's unlikely the `alloc`/`free` signatures will need to change once fixed, and if they do, we'd introduce new `_v2`-suffixed probe names rather than mutate the existing ones in place - old and new samplers can then coexist against old and new profiler versions without a coordinated flag day.

## Background: assumed in-process contract

The profiler's design only makes sense against a rough sketch of what it consumes on the in-process side, even though that side is out of scope to *design* here.

### In-process sampler design

The in-process sampler should follow the existing model converged upon by allocators such as [**jemalloc**](https://github.com/jemalloc/jemalloc/blob/dev/doc_internal/PROFILING_INTERNALS.md) and [**tcmalloc**](https://github.com/google/tcmalloc/blob/master/docs/sampling.md):

- **Random interval sampling over allocated bytes**: the sampler draws the byte distance to the next sample from a geometric distribution, or from an exponential approximation, with mean equal to the configured sampling interval (default ~512 KiB of allocated bytes). Equivalently, this models sampled allocations as a Poisson process over allocation volume.
- A **per-thread byte counter** decremented on every allocation; the fast path is a thread-local add and a branch-predicted-taken comparison. When the counter reaches zero a sample fires and a new geometric interval is drawn.
- For live-heap profiling, the sampler also tracks which pointers were sampled (mechanism is its own concern - see Producing the USDTs in userspace) and fires the `free` USDT only for those pointers. This cannot be done efficiently on the profiler side, as the unsampled free path should add as little overhead as possible.

We provide an [example implementation for the above contract](https://github.com/DataDog/libdatadog/tree/main/libdd-profiling-heap-sampler), with the intention of validating the eBPF profiler-side implementation.

### Producing the USDTs in userspace

The profiler is not prescriptive about how the USDTs end up in a target process. We anticipate three delivery models, all sharing a common core sampling library:

1. **Compile-time allocator wrapping.** A language-specific shim wraps the allocator at compile time (e.g. a Rust `GlobalAlloc` implementation). This is the simplest model and works well when compile time instrumentation is available, and all allocations pass through the single allocator. This breaks down when a statically linked application depends on runtime libraries which cannot be intercepted in this fashion.
2. **Existing allocator observability hooks.** Allocators like jemalloc and tcmalloc expose sampling hooks. A thin adapter registers with these at startup and emits USDTs from the callback. This can also be delivered via `LD_PRELOAD`, where a user preloads e.g. `LD_PRELOAD=jemalloc_with_hooks.so`. Only works for dynamically linked allocators. 
3. **GOT table rewriting.** Whenever `LD_PRELOAD` is not an option, or when simpler packaging is desired (e.g. bundling into an OTel SDK), a shared library is injected and rewrites allocator symbols in the GOT. Most flexible delivery model, but only works for dynamically linked allocators.

For live heap profiling, the free side must recognise which pointers were previously sampled. When using allocator hooks (model 2), this comes from the allocator's built-in book-keeping. When wrapping externally (models 1 and 3), the reference implementation uses hardware pointer tagging (ARM64 TBI) or a per-allocation magic prefix (x86-64) to flag sampled pointers for near-zero-cost detection on every free. See the [reference implementation's tagging documentation](https://github.com/DataDog/libdatadog/blob/main/libdd-profiling-heap-sampler/docs/tagging.md) for details. This tagging is entirely internal to the in-process sampler: the profiler only ever sees the plain `ptr` argument on the `free` USDT and is unaware of how (or whether) a sampled pointer was flagged.

The profiler does not care which of these models is used, which allocator is wrapped, or which language the process is written in; only that the contract above holds and that allocations are sampled according to the description above.

### Expected Runtime Cost

#### In Userspace

On each allocation, the fast path is TLS access, an integer decrement, and a well-predicted branch; only threshold crossings hit the slow path where the sampler draws a new interval and fires the USDT probe. A [USDT semaphore guard](https://github.com/DataDog/libdatadog/pull/2266) short-circuits even earlier: when no profiler is attached the semaphore is zero, so the entire TLS and counter path is skipped after a single memory read.

Measured overhead per alloc/free: ~2.8 ns (arm64, +40%) / ~10.4 ns (x86-64, +99%) when the semaphore is inactive (no profiler attached), and ~14 ns (arm64) / ~54 ns (x86-64) on the sampled slow path with the semaphore active but no profiler attached. Live-heap tracking adds a further ~1.4 ns (arm64 TBI) / ~13 ns (x86-64 header-magic) to sampled allocations only. Percentages are relative to a 64-byte system-allocator round-trip, the smallest (and therefore worst-case) allocation size tested; the sampler's fixed overhead becomes proportionally cheaper as allocation size grows.

#### In eBPF

The profiler-side cost is incurred only for sampled events (one per ~512 KiB of allocation by default). Per-invocation latencies measured via `bpf_stats_enabled` on arm64 (includes the full tail-call unwinder chain, native frame walking and `send_trace`):

| Program | Avg latency | Description |
|---|---|---|
| `uprobe_heap_alloc` | ~4.7 µs | Arg extraction, `heap_alloc_live` insert, per-PID limit check, stack unwind |
| `uprobe_heap_free` | ~0.6 µs | Map lookup + delete, `send_trace`, no stack walk |
| `native_tracer_entry` (CPU profiler) | ~3.0 µs | Full CPU sample for comparison |

Projected overhead at various allocation rates (assuming ~1:1 alloc:free ratio):

| Allocation rate | Samples/sec | eBPF CPU time/sec | % of 1 CPU-second |
|---|---|---|---|
| 10 MiB/sec | 20 alloc + 20 free | 107 µs | 0.011% |
| 50 MiB/sec | 100 + 100 | 534 µs | 0.053% |
| 100 MiB/sec | 200 + 200 | 1,068 µs | 0.107% |

Measurements taken on an Apple M3 Max (ARM64, 64 GB) MacBook Pro, running Linux in a VM under Apple's Virtualization framework.

For comparison, the CPU profiler measured on the same system at its default 20 Hz consumes ~61 µs/sec (0.006%) per CPU.

We are exploring dynamic sample distance adjustment on the client side, where the sampler adapts its sampling interval to target a fixed number of samples/sec regardless of allocation rate, bounding the profiling overhead to a predictable ceiling.

## USDT discovery

USDT notes are emitted into `.note.stapsdt` ELF sections. For each process the profiler tracks, we scan the executable file-backed mappings, parse their `.note.stapsdt` section, filter to our provider, and translate probe names to a small fixed `ProbeKind` enum (`ProbeHeapAlloc`, `ProbeHeapFree`). This enum is expected to grow (e.g. `ProbeHeapMmap`, `ProbeHeapMunmap`) as the `mmap`/`munmap` probes land in subsequent work.

Parsing is delegated to [`github.com/parca-dev/usdt`](http://github.com/parca-dev/usdt). This avoids hand-rolling SystemTap SDT note parsing while keeping the existing `cilium/ebpf` runtime for attachment - we get the parser without adopting a second eBPF stack. This Polar Signals library is already being used successfully in Polar Signals' downstream fork of the full-host profiler and would benefit the community to be upstreamed to support this work.

Parse results are cached by `OnDiskFileIdentifier`, so a `.so` mapped by many processes is parsed once. Probe-less binaries are also cached (empty result) to avoid re-scanning on every reconcile.

## Per-process attachment and lifecycle

Uprobes are attached **per-PID** using cilium/ebpf's `UprobeOptions.PID`, not globally per binary. Memory profiling is a per-process decision and PID-scoped links fit the existing `ProcessManager` lifecycle.

A new `usdt.Manager` owns the global parse cache and the BPF programs; a per-PID `usdt.Instance` owns that PID's live `link.Link` attachments, keyed by `(PID, FileID, Kind, Offset)`.

Reconciliation runs on **every** `ProcessManager.SynchronizeProcess` call (not only on first sight of a PID), diffing the set of expected probes against the set currently attached for the PID. This is what catches `.so`s that were `dlopen`'d after the process started - the most important case in practice for Python workloads.

Detach happens in `processPIDExit` alongside the existing interpreter teardown.

## eBPF entry programs

Two new eBPF programs, `uprobe_heap_alloc` and `uprobe_heap_free`. They:

1. Read USDT arguments out of `pt_regs` via a small arch-specific helper.
2. Tail-call into the existing native unwinder via `collect_trace`, tagging the trace with a new origin (`TRACE_HEAP_ALLOC`) and passing `weight` through as the trace value. This is the same shape used by the off-CPU entry program.
3. For free: short-circuit if `(pid, ptr)` is not in our sampled allocation correlation map. This keeps the hot path cheap.

The `uprobe_heap_free` program is loaded into the kernel only when `-live-heap-profiling` is enabled. When only `-allocation-profiling` is on, the program isn't loaded and the `free` USDT isn't attached, so plain allocation profiling pays only the alloc-side cost.

## Reporting / OTLP structure

Two sibling profiles share the alloc call stacks and timestamps:

- `sample_type = alloc_space/bytes` - values are USDT `weight`.
- `sample_type = alloc_objects/count` - value is `1` per event; aggregation gives the number of allocation events captured.

When live-heap profiling is enabled, the free program decrements the correlated allocation's contribution; we additionally emit:

- `sample_type = inuse_space/bytes`
- `sample_type = inuse_objects/count`

These four sample types follow standard pprof / OTLP profile conventions.

## Back-pressure

Allocation USDTs are expected to fire more frequently than perf samples even after in-process sampling. Back-pressure is layered at two points:

- **In-process: open-loop random-interval sampling** (see Background: assumed in-process contract for the mechanism). This is open-loop - the application has no idea what the profiler is currently doing - and gives an unbiased estimator via `weight`. Cheap, simple, and the primary cost of the book-keeping is accessing the TLS to track state. This is also the approach used by samplers such as jemalloc and tcmalloc in their own observability infrastructure; by supporting the ecosystem where it is, we increase the chances of being able to influence allocators to include sampling hooks by default when this method shows adoption.
- **eBPF / collector side: closed-loop PID control.** The profiler maintains a target rate of memory events (expressed as a fraction of the overall sample budget) and runs a PID controller in user space that adjusts a drop probability applied inside the `uprobe_heap_alloc` eBPF program. The controller observes the measured event rate, compares it against the target, and updates the threshold so that memory events occupy a bounded share of the payload regardless of workload spikes.

We also anticipate a future in-process addition: dynamic interval adjustment, where the sampler targets a fixed samples-per-second rate and self-adjusts its interval to hit it. This is purely a sampler-side concern - it doesn't change the USDT contract and the profiler doesn't need to know it's happening.

Notes on the controller:

- The controlled variable is a per-CPU drop threshold read by the eBPF program at the top of `uprobe_heap_alloc`; the eBPF side does one compare-and-bail.
- The setpoint is `target_memory_events_per_sec`, derived from the existing sample budget multiplied by a configurable memory fraction. Memory events cannot starve on-CPU profiling because the budget is apportioned, not shared.
- Dropped events are still counted (so we can surface drop ratios as a metric and ultimately fold the drop probability back into `weight` for unbiased totals).
- The controller's tuning constants and the target memory fraction are to be determined empirically; see Plan to Acquire Missing Data.
- The controller bounds memory-event throughput, but it does not by itself bound the amount of live allocation state retained for `inuse_*` profiles. Live heap tracking therefore also requires explicit global and per-process state limits, described below.

### Live heap state bounds

Sampled allocations awaiting a matching free are tracked in a live-heap correlation map, keyed by `(pid, ptr)` (this is the same map `uprobe_heap_free` consults - see eBPF entry programs). This map is bounded by both a global cap and a per-process cap. When either cap is reached, we simply stop accepting new elements into the map: further sampled allocations are not added to live-heap tracking until existing entries are freed and their slots released. This only affects `inuse_*` accounting - the `alloc_space`/`alloc_objects` profiles are unaffected, since those are produced directly from the alloc-side event and don't depend on the correlation map. As an aside, we already emit drop-ratio metrics for the PID controller (above); the live-heap cap gets the same treatment, so operators have visibility into both throttling paths.

Because `uprobe_heap_free` only decrements state for pointers it finds in the correlation map, an allocation dropped for being over-cap is simply never seen by the corresponding free - the same behaviour as an allocation dropped by the PID controller.

The two layers are independent: the in-process sampler is unaware of the controller, which keeps the hot path branch-prediction-friendly and allocator-agnostic.

# Alternatives Considered

- Attach to kernel tracepoints **`sys_enter_brk`** / **`sys_enter_mmap`** /etc. Too far from application allocation patterns: modern allocators go to great lengths to avoid kernel calls, so most allocations are invisible at this layer. Down the road, this might be useful to help us catch `mmap`s that do not go through libc.
- **Attach uprobes to allocator-specific internal sampling paths (`jemalloc`, `tcmalloc`)** - we discount this approach as it is fragile against the internals of the allocators, the allocators do not by default have sampling turned on (or if it is turned on, it may do more work than we want - for instance, with jemalloc and its optional stack-collection behaviour in the sampling path), and does not generalise to all allocators. Additionally, allocators are frequently statically linked, meaning there is no predictable symbol to attach to - internal names and inlining decisions vary across versions and build configurations.
- **Sample every alloc/free.** Prohibitive overhead; allocators are on the critical path for most workloads.
- **Global (per-binary) uprobe attachment** rather than per-PID. Loses the ability to opt processes in/out individually and complicates cleanup; doesn't fit the profiler's existing lifecycle model.
- **Hand-rolled `.note.stapsdt` parsing.** Pointless given the `parca-dev/usdt` parser already exists, is small, and is permissively licensed.

# Author's Preferred Solution

The proposal above is the preferred design. The two non-obvious calls are:

- **Treating the in-process sampler as an external contract** rather than bundling it. This keeps the upstream surface area small and lets multiple in-process implementations (a Rust `GlobalAlloc` wrapper, a runtime-injected `.so`, an upstream jemalloc patch in future) all target the same profiler.
- **Gating the free path behind a separate flag.** Allocation profiling is enormously useful on its own, and free-side machinery is the only part that needs a correlation map and pays cost on every free of a sampled pointer. Splitting the flags lets users opt into the cheaper mode.

Long term, we'd like common allocators (`jemalloc`, `tcmalloc`, `glibc`) to emit the `otel_memory` USDTs directly, so users get memory profiling without changing their applications. This doesn't change the design here: the USDT contract stays exactly as specified, it's just satisfied by the allocator itself rather than a wrapper. We hope adoption of this proposal by the OpenTelemetry community helps incentivise that upstreaming. In the meantime we've begun looking at using upstream sampling APIs directly, for instance [extending the Rust jemalloc crate](https://github.com/tikv/jemallocator/pull/172) so existing Rust jemalloc users can benefit from this profiling without additional libraries.

# Testing Strategy

## Testing of Proposed Solution Itself

- **Unit tests** for: USDT note parser adapter, provider/probe-name filtering, the reconcile diff (probes added on `dlopen`, removed on `munmap`/exit).
- **Integration tests** using small Rust and C test binaries that emit the contract USDTs with deterministic allocation/free patterns; assert OTLP output shape, value sums, and sample counts. A PoC of this kind already exists on the [`sgg/heap-prof-poc`](https://github.com/DataDog/opentelemetry-ebpf-profiler/tree/sgg/heap-prof-poc) branch and can be cleaned up into the upstream test suite.
- **Lifecycle coverage** for fork, exec, `dlopen`-after-start, exit, short-lived processes.
- **Negative tests**: process without our USDTs (nothing attaches); process with USDTs but `-allocation-profiling` not set (nothing attaches); `-live-heap-profiling` without `-allocation-profiling` (rejected at flag parse).

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
