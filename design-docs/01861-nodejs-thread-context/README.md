Node.js Thread Context
======================

# Meta

- **Author(s)**: Attila Szegedi
- **Start Date**: 2026-09-14
- **Goal End Date**: TBD
- **Primary Reviewers**: [https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers](https://github.com/orgs/open-telemetry/teams/ebpf-profiler-maintainers)

# Abstract

This document proposes how the profiler reads OpenTelemetry thread context from
Node.js processes. [OTEP 4947](https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4947-thread-ctx.md)
specifies that the target process publishes a pointer to a **Thread-Local
Context Record** in a thread-local variable and the profiler dereferences it.
That mechanism does not fit Node.js, where a single thread interleaves many
logical contexts and keeping a thread-local current would mean an FFI crossing
on the hottest path in the runtime.

We propose a second discovery mechanism for the same record format. The target
process publishes a small discovery struct in a thread-local; the profiler uses
it to walk through thread-specific V8 and Node.js data structures until it
reaches the record attached to the asynchronous local storage of the current
execution. The record format, attribute key map handling, and all record parsing
are shared verbatim with OTEP 4947, and the new walk is selected by a distinct
`threadlocal.schema_version` value. The design has a working writer-side
[reference implementation](https://github.com/polarsignals/custom-labels/tree/otel-thread-ctx-wip/js);
and this document is the proposal for making the profiler read it.

This is a design document rather than a new OTEP because its scope is too narrow
for one: it concerns a single runtime, and what it specifies is how this
profiler reads it. It changes nothing that OTEP 4719 or 4947 specify, and it
needs no new specification, only the extension points those OTEPs already
provide: a new schema version value, and few more process-context keys.

# Introduction

## Context

Two OTEPs define what the profiler consumes today:

- [OTEP
  4719](https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4719-process-ctx.md)
  defines **Process Context**: process-scoped data the profiler reads once
  rather than per sample.
- [OTEP
  4947](https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4947-thread-ctx.md)
  defines the **Thread-Local Context Record**, a packed byte layout carrying
  trace ID, span ID, trace flags and indexed attributes, as well as the
  thread-local variable that points at it. It surveys the major runtimes and
  lists Node.js among those it does not expect to support, with a section,
  "Alternative for Node.js support", promising a separate document. This is that
  document, adapted for this repository.

Relevant code already in or arriving in this repository:

- the `processcontext` reader reads OTEP 4719 process context, and gates
  thread-context support on the `threadlocal.schema_version` it finds there.
- `threadcontext` code locates OTEP 4947's thread-local, across whichever TLS
  access model the target was built with, and decodes the record it points at.
  **Nearly all of this is reusable as-is**: what this proposal changes is the
  size and interpretation of what the thread-local holds, not how it is found.
- `interpreter/nodev8` already unwinds V8 JavaScript stacks, which means the
  profiler already reads tagged V8 words and V8 heap object fields out of
  target memory. The walk proposed here needs the same primitives.
- `design-docs/00002-custom-labels` is the sibling mechanism for Go pprof
  labels, which also has a unit of context other than the OS thread.

### How Node.js tracks the active continuation

Node.js interleaves many logical threads of execution on one OS thread, which is
what makes OTEP 4947 unaffordable there; "Problem" below states that case. The
consequence for this section is that the unit which has to be tracked is not the
OS thread but the active *continuation* — the remainder of a computation, which
in Node.js terms is the logical thread of execution that resumes when a promise
settles, a callback fires or a timer expires.

Node.js already has a way to attach data to one, and the mechanism acts on two
levels:

- **V8** provides `ContinuationPreservedEmbedderData` (CPED), a per-isolate slot
  holding one value that V8 exchanges as it moves between continuations. V8
  attaches no meaning to the value; it only guarantees that the slot tracks the
  active continuation. An **isolate** is the V8 instance of a JavaScript runtime
  with its own isolated heap. Node.js creates exactly one isolate for each
  thread executing JavaScript, so threads map to isolates one-to-one.
- **Node.js** decides what to put there. When its `AsyncLocalStorage` is backed
  by **`AsyncContextFrame`** (a Node.js construct, not a V8 one) the value in
  the CPED slot is an async-context frame, realized as a JavaScript `Map` from
  each live `AsyncLocalStorage` instance to its current store. Node.js also
  installs the right `AsyncContextFrame` into the CPED slot on the continuation
  changes it effects itself, such as entering IO and timer callbacks.

Said otherwise, CPED is the V8 mechanism and the async-context frame is Node's
application of it. An SDK, or any other Node.js tracing code, that puts its
record holder into an `AsyncLocalStorage` therefore gets context-switch tracking
for free, at exactly the granularity the runtime uses, with no native call on
attach or detach and no cost at all when nothing is attached.

What is left is to tell the profiler how to walk from the isolate to the record.
That is what this document specifies.

### Reference implementations

The writer side exists and has been exercised:

- [`polarsignals/custom-labels`, `js/`
  directory](https://github.com/polarsignals/custom-labels/tree/otel-thread-ctx-wip/js)
  — reference implementation of this contract, including the reader-facing
  contract documented in its `README.md`.
- [`DataDog/pprof-nodejs`](https://github.com/DataDog/pprof-nodejs) — the same
  writer vendored into a shipping profiler.

The discovery approach — walking the async-context frame out of the CPED slot —
was first demonstrated by Polar Signals ([blog
post](https://www.polarsignals.com/blog/posts/2025/11/19/custom-labels-for-node-js)),
and OTEP 4947 points at it as the likely direction for Node.js. This proposal
adopts that idea and adapts it to OTEP 4947's record format and OTEP 4719's
process context.

## Problem

Node.js's concurrency model relies on a single thread per isolate that is used
to multiplex many logical contexts, switching between them constantly.

While Node.js does offer callbacks for detecting these context switches, they
carry high costs — installing custom code in the promise-switching path
deoptimizes V8 — and they are deprecated and slated for removal.

This combination of constant switching and the high cost of running code at each
switch means a straightforward implementation of OTEP 4947 would not be
efficient for Node.js. Running code at each switch is already expensive; an FFI
crossing at each switch to update the record pointer in the OTEP 4947 native
thread-local would be even worse. Avoiding running code and especially native
code on every switch is what we want to achieve below.

Similarly to how Go is already supported under its own schema version, we
propose a Node.js-specific discovery mechanism for the same record format.

## Success Criteria

- **The record format is reused unchanged.** The bytes the profiler parses are
  identical to OTEP 4947's, so record parsing and `attribute_key_map` decoding
  are shared across runtimes. Only the code that finds the record differs.
- **Selection is explicit.** The new walk is chosen by a distinct
  `threadlocal.schema_version` value, so a target the profiler does not
  understand degrades to no context rather than to a wrong walk.
- **The TLS-location machinery is shared.** Locating the discovery struct reuses
  `interpreter/threadcontext`'s existing access-model handling rather than
  duplicating it.
- **No native call on the target's context-switch path.** Attach and detach in
  the target must be ordinary `AsyncLocalStorage` operations, or the mechanism
  will not be adopted by SDKs.
- **Zero marginal cost in an uninstrumented target.** A process that never
  attaches context must be indistinguishable from today.
- **Per-worker-thread correctness.** Each Node.js worker thread has its own
  isolate and must be independently observable.
- **A mis-stepped walk yields no sample, not a wrong one.** Every step is
  gated or validated such that garbage is rejected rather than reported as a
  trace ID.
- **Not eBPF-specific.** As with OTEP 4947, any reader able to read
  `/proc/<pid>/maps` and target process memory should be able to implement this.

## Scope

### In scope

- The contract the profiler expects a Node.js target process to publish: process
  context attributes, the discovery struct, and the ordering rules that make it
  safe to read from a stopped thread.
- The walk from the discovery struct to the record, and where it hooks into
  `process/processcontext` and `interpreter/threadcontext`.
- Validation and failure behaviour for each step of the walk.
- How the walk is tested.

### Non-success criteria / out of scope

- **Implementing the writer side.** The contract is specified here and has
  reference implementations, but shipping it in
  [`opentelemetry-js`](https://github.com/open-telemetry/opentelemetry-js) or
  any vendor SDK is separate work.
- **Node.js configurations where `AsyncLocalStorage` is not backed by
  `AsyncContextFrame`.** See "Runtime requirements"; such targets do not publish
  the schema version and are simply not supported.
- **Non-Linux platforms.** As in OTEPs 4719 and 4947, the discovery contract is
  ELF/TLSDESC-based. The record format and the CPED walk are not Linux-specific;
  only the mechanism for finding the discovery struct is.
- **Attributing work that runs outside the isolate's own thread.** Node.js
  dispatches filesystem, DNS, zlib and asynchronous crypto work to the libuv
  thread pool, and those threads run no JavaScript and host no isolate, so they
  never publish a discovery struct. There is currently no mechanism in Node.js
  we could use to support this thread pool; such a mechanism would mean changing
  Node.js itself.

# Proposed Solution

## Resolving the context

"The SDK" below is shorthand for whichever component in the target publishes the
context — an OpenTelemetry SDK, a vendor tracer, or any other Node.js tracing
code. Such a component publishes context by:

1. Creating one `AsyncLocalStorage` instance per isolate, and telling its native
   addon about it.
2. Allocating a **Thread-Local Context Record** behind a JavaScript wrapper
   object for every tracing span, and storing a raw pointer to the record in the
   wrapper's internal field.
3. Attaching context by storing that wrapper in the `AsyncLocalStorage` (and
   detaching it by storing `undefined`). Both are pure-JavaScript operations; no
   native code runs for them.

Only step 3 is on the hot path, and only when the wrapper from steps 1 and 2 is
reused — which is the intended pattern, an SDK caching both on the span so that
re-entering a context allocates nothing and calls no native code. An SDK may
also start with a small record and grow it as attributes accumulate.

The profiler walks:

```text
otel_thread_ctx_nodejs_v1 (TLS)  →  *cped_slot  →  AsyncContextFrame (a JS Map)
  →  look up the published AsyncLocalStorage instance as key
  →  the wrapper JSObject that is its value
  →  internal field 0  →  Thread-Local Context Record
```

A single ELF thread-local named `otel_thread_ctx_nodejs_v1` is still involved,
but it holds **discovery data, not a record pointer**. Its contents are fixed
for the life of the isolate, so it is written once at initialization rather than
on every context switch. This is the essential difference from OTEP 4947 and the
reason the mechanism is affordable in Node.js.

The cost is moved to the profiler: to find the record it must know enough about
V8 and Node.js internals to read their representation of a JavaScript `Map`. See
"Trade-offs and mitigations" below for more details.

## The contract the target process provides

### Process context attributes

As in OTEP 4947, process-scoped data is published as entries in
`ProcessContext.attributes` per OTEP 4719, so the profiler reads it once rather
than per sample. This proposal uses the existing values with an alternate
`threadlocal.schema_version`; it adds no new process attributes.

Reused from OTEP 4947:

- `threadlocal.schema_version` — `nodejs_v1_dev` for experimentation, to become
  `nodejs_v1` once this doc gets merged. Recognizing this value is what tells
  the profiler to use the walk described here instead of OTEP 4947's TLS-pointer
  walk.
- `threadlocal.attribute_key_map` — unchanged, including its append-only
  semantics.

Example:

```yaml
key: "threadlocal.schema_version"
value:
  string_value: "nodejs_v1_dev"

key: "threadlocal.attribute_key_map"
value:
  array_value:
    values:
      - string_value: "http.request.method"  # index 0
      - string_value: "http.route"           # index 1
```

> **Note:** As in OTEP 4947, the `threadlocal.*` keys are inter-process
> coordination metadata rather than telemetry attributes, and are not expected
> to appear in OTLP exports.

### Thread-local variable

A single thread-local, `otel_thread_ctx_nodejs_v1`, is exported as an ELF TLS
symbol in the dynamic symbol table, providing the information specific to the
Node.js runtime needed to find the OTEP-4947 record. It is a struct, not a
pointer:

| Name | Offset | Data type | Notes |
| :--- | :----- | :-------- | :---- |
| `cped_slot` | `0` | pointer | Address of this thread's isolate's `ContinuationPreservedEmbedderData` slot. The slot holds a tagged V8 word; dereferencing it yields the active Node.js `AsyncContextFrame`. Lets the profiler reach the active frame without any V8 internal symbol lookup. Doubles as the **gate**: an all-zero value means the SDK has not published on this thread, has torn it down again, or has closed the gate temporarily, and no other field may be used while it reads zero. |
| `als_handle` | `sizeof(void *)` | pointer | A `v8::Global<Object>` referring to the published `AsyncLocalStorage` instance in this thread's isolate. Its representation is a single V8 internal pointer; dereference it to obtain the instance's tagged address, which is the key to look up in the frame. |
| `als_identity_hash` | `2 * sizeof(void *)` | int32 | The JS identity hash of that instance, so the profiler can restrict its search to one hash bucket rather than scanning every entry. |
| `record_slot_offset` | `2 * sizeof(void *) + 4` | uint8 | Byte offset, within the wrapper `JSObject`, of the slot holding the pointer to its record. See "The V8 layout constants the walk uses" below for details. |
| reserved | `2 * sizeof(void *) + 5` | 3 bytes | Zero. Readers MUST ignore them. |
| `undefined_addr` | `3 * sizeof(void *)` | tagged word | This thread's isolate's tagged address of the `undefined` singleton. Lets the profiler detect "no context attached" by comparison, rather than by structurally validating whatever the frame maps our key to. |

`cped_slot`, `als_handle`, `als_identity_hash` and `undefined_addr` are fixed
while the isolate lives, but they are not written only once: the SDK populates
them when it installs its hook and zeroes them again at teardown.
`record_slot_offset` is a property of the SDK's build rather than of the
isolate, so an SDK MAY set it statically, and need not clear it at teardown.

Additionally, a writer MAY temporarily set the `cped_slot` to zero and later
restore its previous value if it wishes to prevent reads for a period of time
because some condition makes the walk unsafe — see "Garbage collection" for a
motivating example.

The profiler MUST therefore re-read at least the `cped_slot` each time it
samples the thread, and MUST NOT substitute cached values for other fields when
it changes. The profiler also MUST NOT infer from a zero reading that a thread
is permanently uninstrumented.

Upon initialization implementations MUST write the nonzero `cped_slot` value
last, and upon isolate teardown they MUST write the zero `cped_slot` value
first, using compiler fences (`atomic_signal_fence` or equivalent) and volatile
writes to prevent instruction reordering by the compiler. This way the profiler
is guaranteed to always see a fully populated struct when `cped_slot` is
nonzero.

The TLS access-model requirements of OTEP 4947's "Thread-Local Variable
Resolution" apply unchanged: writers SHOULD use the TLSDESC dialect, and readers
MUST support Global Dynamic/TLSDESC, Global Dynamic/legacy GNU, and
linker-relaxed initial-exec or local-exec access. This is exactly what
`interpreter/threadcontext` already implements.

Because Node.js pins each isolate to a thread and creates a fresh isolate per
worker thread, a thread-local struct is the natural home for this data: each
worker thread that installs the hook publishes its own `cped_slot`, its own
`AsyncLocalStorage` instance and its own `undefined_addr`, and is independently
observable. Threads that never install the hook leave the struct zeroed, which
is what lets `cped_slot` serve as the gate: no live isolate has its CPED slot at
address zero.

### Thread-local context record

Unchanged from OTEP 4947, including field offsets, `attrs-data` encoding, the
`valid` byte, the 2-byte alignment requirement, the last-occurrence-wins rule
for repeated key indexes, and the recommendation to keep the total record at or
under 640 bytes. The profiler MUST be able to use the same parser for both
schemas.

### Publication protocol

Every requirement below exists because the profiler's correctness depends on it:
it is the set of assumptions the reader makes, restated as obligations on the
target. Where an SDK is free to choose, this section says `MAY` or says nothing.
Writer behavior the profiler cannot observe is not in scope for this document.

#### 1. Isolate initialization

On first use, per isolate, the SDK:

1. Verifies that `AsyncLocalStorage` is backed by `AsyncContextFrame` (see
   "Runtime requirements").
2. Creates one `AsyncLocalStorage` instance dedicated to this mechanism.
3. Populates `otel_thread_ctx_nodejs_v1` with the four fields above, writing
   `cped_slot` **last**, as a volatile store preceded by a compiler fence.
   Publishing the gate after everything it guards means a reader either sees
   zero and stops, or sees a fully populated struct.
4. Publishes the process context attributes above per OTEP 4719. This
   publication is idempotent, so it can be repeated on every isolate
   initialization, but an implementation MAY publish it only once per process.

The `AsyncLocalStorage` instance SHOULD NOT be exposed to application code, so
that nothing but the SDK can put values into the slot the profiler trusts.

#### 2. Context attachment

When context becomes active, the SDK:

1. Allocates a **Thread-Local Context Record**, writes the trace context and any
   configured attributes into it, and sets `valid` to 1 last, ordered with a
   compiler fence and a volatile store as OTEP 4947 requires.
2. Allocates a new JavaScript object with an internal field, and stores a raw
   pointer to the record in that internal field. This publication step is what
   makes the record reachable; until it happens, no reader can observe a
   partially built record.
3. Stores the wrapper in the `AsyncLocalStorage`, for a scope or until replaced.

A record MUST stay alive for as long as its wrapper is reachable in the
JavaScript heap, since any such wrapper can still be presented to the profiler;
it may be released once the wrapper is known to be unreachable.

#### 3. Context detachment

A wrapper stored in an `AsyncLocalStorage` stays reachable from every
async-context frame derived from the one it was stored in, so several frames can
present the same record at once. That gives detachment two mechanisms, for two
different scopes:

- **Detach from the current frame** — store `undefined` in the
  `AsyncLocalStorage`. This affects the current frame and frames derived from
  it. Sibling frames and detached continuations that hold the same wrapper
  reference are unaffected and continue to present the record. This is used when
  the span is not finished yet but is no longer associated with the current
  asynchronous execution.
- **Invalidate the record** — set the record's `valid` byte to 0 in place,
  ordered with a compiler fence and a volatile store. Because every frame
  holding the wrapper reference sees the same record, this single write drops it
  out of scope for all of them at once. This is used when the span ends.

An SDK SHOULD invalidate on span end rather than relying on detachment alone, or
the profiler may keep observing an ended span's identity on frames that were
never explicitly cleared. Regardless, an SDK MAY also detach from the current
frame when the span ends in addition to invalidating the record.

#### 4. Growing the attribute payload

OTEP 4947 permits appending to `attrs-data` in place, publishing the new extent
by writing `attrs-data-size` last. That applies here unchanged when the existing
allocation has room.

When it does not, a writer that has to move the record MUST re-publish the new
record's address into internal field 0 of the **same** wrapper object, ordered
after all writes to the new record, and MUST NOT replace the wrapper. Because
every frame reaches the record through the wrapper, this keeps the append
visible to all of them, with the internal-field store as the single atomic
boundary the reader observes. The old record may be released immediately
afterwards under OTEP 4947's signal-handler semantics, provided the release
cannot be reordered before that store.

#### 5. Isolate teardown

Before an isolate is torn down, the SDK MUST clear the thread-local, and MUST
clear `cped_slot` **first**, as a volatile store followed by a compiler fence.

After `cped_slot` was zeroed, the profiler stops reading and will thus never
reach any data (potentially in already freed memory) that belonged to the
isolate.

### Runtime requirements

The mechanism requires `AsyncLocalStorage` to be backed by `AsyncContextFrame`,
since that is what puts the store map into the CPED slot. In Node.js this is
available from 22.7.0 behind `--experimental-async-context-frame`, and on by
default from Node 24, where it can still be turned off with
`--no-async-context-frame`.

An SDK MUST feature-detect this rather than infer it from the version and
command line, which disagree in both directions: `NODE_OPTIONS` can enable or
disable it without appearing in `process.execArgv`, and worker threads may be
created with a different `execArgv` than the main thread.

The schema also presumes the V8 Node.js builds by default: 64-bit, pointer
compression off, the V8 sandbox off. This fixes V8's object layout; "The V8
layout constants the walk uses" section further below says what that covers. An
SDK running on a V8 built with pointer compression or the sandbox enabled MUST
NOT declare the schema version from this document, since its object layout does
not match it.

An SDK that cannot satisfy these requirements MUST NOT publish
`threadlocal.schema_version`.

## Changes in the profiler

### Where this hooks in

The proposal is additive at three points, in increasing order of new code:

1. **`process/processcontext`** — accept `nodejs_v1_dev` (and later `nodejs_v1`)
   alongside `tlsdesc_v1_dev` as a supported `threadlocal.schema_version`. No
   new attributes are parsed and the `attribute_key_map` handling is untouched.
   The schema version must be carried forward so the sampling path can select a
   walk.
2. **`interpreter/threadcontext`** — a second TLS export name,
   `otel_thread_ctx_nodejs_v1`, and a 4-word struct where the existing schema
   has a single 8-byte pointer. The TLS access-model resolution, the symbol and
   relocation matching, and the `TLSVarInfo` plumbing shared with `apmint` are
   reused unchanged: locating a thread-local is the same problem regardless of
   what it holds.
3. **The walk itself** — new code, reading V8 heap objects out of target memory.
   `interpreter/nodev8` establishes the primitives (tagged word handling,
   bounded remote reads of V8 objects) but this walk is independent of stack
   unwinding and should not be entangled with the unwinder's state. Prior art
   for a similar walk is found in
   [Polar Signals' eBPF profiler](https://github.com/parca-dev/opentelemetry-ebpf-profiler/blob/main/support/ebpf/native_custom_labels.h).

### 1. Process initialization

Unchanged from OTEP 4947's process-initialization steps, except that the
profiler looks for `otel_thread_ctx_nodejs_v1` in the dynamic symbol tables, and
treats a `threadlocal.schema_version` of `nodejs_v1` or `nodejs_v1_dev` as
selecting this walk.

### 2. Thread sampling

As in OTEP 4947, the profiler MUST only read while the target thread is stopped
or interrupted.

The pseudo-code below assumes the build this schema presumes: 64-bit, with
pointer compression and the V8 sandbox both off, which is how Node.js is built
by default. The layout constants it opens with are fixed by the schema version
rather than read from the target, except for the record slot offset, which the
struct carries; "The V8 layout constants the walk uses" below covers all four.
**Tagged values** can either be small integers ("Smi" in V8 parlance) or
pointers stored in a single machine word. Pointers have their low bit set,
that's the tag; clear it to get the object address. Smis use the upper 32 bits
of the word to represent signed integer values and thus need to be right-shifted
by 32 bits to get the actual value.

```cpp
// Fixed by the schema version, not read from the target; see below.
constexpr size_t kTaggedSize = 8, kJSMapTableOffset = 24,
                 kOrderedHashMapHeaderSize = 16;

auto* ctx = read_tls<otel_thread_ctx_nodejs_v1_t>();
if (ctx->cped_slot == 0) return NO_CONTEXT;  // nothing published here
size_t record_slot_offset = ctx->record_slot_offset;
// A slot is always tagged-word aligned
if (record_slot_offset % kTaggedSize != 0) return NO_CONTEXT;
// No async-context frame is active.
if (*ctx->cped_slot == ctx->undefined_addr) return NO_CONTEXT;

// CPED -> active AsyncContextFrame (a JS Map) -> its backing OrderedHashMap.
auto* acf = untag<JSMap>(*ctx->cped_slot);
auto* table =
    untag<OrderedHashMap>(*(uintptr_t*)((char*)acf + kJSMapTableOffset));

// Find the value keyed by our AsyncLocalStorage instance. A reader uses the
// published identity hash to walk a single bucket; find_value is sketched
// separately below.
uintptr_t als = *ctx->als_handle;
uintptr_t value = find_value(table, als, ctx->als_identity_hash);
if (value == 0) return NO_CONTEXT;  // not in this frame
if (value == ctx->undefined_addr) return NO_CONTEXT;  // explicitly detached

// The value is the wrapper JSObject; internal field 0 holds the record pointer.
auto* wrapper = untag<JSObject>(value);
auto* record =
    *(OtelThreadCtxRecord**)((char*)wrapper + record_slot_offset);
if (record == nullptr) return NO_CONTEXT;  // teardown in progress
if (record->valid != 1) return NO_CONTEXT;  // invalidated or mid-update
// Parse exactly as in OTEP 4947 from here on.
```

Both `NO_CONTEXT` exits before the `JSMap` walk are cheap, and the second is the
common case for a process that is not currently serving a request — which is why
`undefined_addr` is published rather than left for the profiler to infer
structurally. The first tests the very pointer the next line dereferences, so it
needs no assumption about any other field.

As in OTEP 4947, the profiler SHOULD validate before trusting: a mis-stepped
pointer walk yields garbage at the same offsets. The `OrderedHashMap` carries
enough redundancy that checking it is cheap, and the checks fall out of the
lookup itself, so `find_value` is sketched below with them folded in. Tagged
words are checked for their tag before use rather than assumed to be of the
kind the layout calls for; the element count in particular can hold a pointer
instead of a Smi, for reasons "Mutation of the frame map while it is read"
below explains.

```cpp
// A V8 OrderedHashMap is a V8 FixedArray: header, then `length` tagged words.
// The first three are counts; then one bucket head per bucket; then the
// entries, three words each (key, value, chain).
constexpr int kEntrySize = 3, kLoadFactor = 2, kNotFound = -1;

// Returns the value tagged word, or 0 — not a valid tagged value — when the
// key is absent or the table does not check out.
uintptr_t find_value(void* table, uintptr_t key, int hash) {
  auto* t = (char*)table;
  auto at = [&](size_t off) { return *(uintptr_t*)(t + off); };
  // i-th word of the array proper, past the FixedArray header.
  auto word = [&](int i) {
    return at(kOrderedHashMapHeaderSize + i * kTaggedSize);
  };

  // The array length is the second word of the header.
  auto len = at(kTaggedSize);
  if (!is_smi(len) || smi(len) < 3) return 0;  // no room for the counts

  auto n = word(0), d = word(1), b = word(2);
  if (!is_smi(n) || !is_smi(d) || !is_smi(b)) return 0;
  int elements = smi(n), deleted = smi(d), buckets = smi(b);

  // Number of buckets must be a power of two.
  if (buckets <= 0 || (buckets & (buckets - 1)) != 0) return 0;
  int capacity = buckets * kLoadFactor;
  if (elements < 0 || deleted < 0 || elements + deleted > capacity) return 0;
  // Everything the map claims to hold has to fit in the array.
  if (smi(len) < 3 + buckets + kEntrySize * capacity) return 0;

  // Entries are appended in insertion order, so only the first `used` of the
  // `capacity` slots are populated and every index must be below it.
  int used = elements + deleted;

  // Get the head entry of the target hash bucket
  auto head = word(3 + (hash & (buckets - 1)));
  int entry = is_smi(head) ? smi(head) : kNotFound;

  // Bounding the walk by `used` keeps a corrupt or cyclic chain from looping
  // forever; a well-formed chain ends at kNotFound well before that.
  for (int steps = used; steps > 0 && entry >= 0 && entry < used; steps--) {
    int i = 3 + buckets + entry * kEntrySize;
    if (word(i) == key) return word(i + 1);
    auto next = word(i + 2);
    entry = is_smi(next) ? smi(next) : kNotFound;
  }
  return 0;
}
```

The load factor of two is hardcoded in V8, as is the three-word entry; "The V8
layout constants the walk uses" below covers the rest of what this sketch
assumes.

This document does not prescribe validation of the record itself, as such
validations are presumed to already exist in the common record parsing code to
ensure it is not reading garbage.

### The V8 layout constants the walk uses

Three of the constants the pseudo-code uses are not read from the target. This
schema fixes them, so a reader holds them as it would any protocol constant,
pinned by `schema_version`:

| Constant | Value | What it is |
| :------- | ----: | :--------- |
| `kTaggedSize` | 8 | V8's tagged-pointer width in bytes. |
| `kJSMapTableOffset` | 24 | Byte offset, within a V8 `JSMap`, of the tagged pointer to its backing `OrderedHashMap` table. |
| `kOrderedHashMapHeaderSize` | 16 | Size of the header preceding the table's element-count fields. |

All three are functions of two V8 build switches, pointer compression and the V8
sandbox. This schema version disallows both of them. An SDK compiled with either
MUST NOT declare the schema, per "Runtime requirements" above. If they ever need
supporting, a later schema version can be introduced.

On the writer's side the values can be checked because all three follow from
constants in V8's `v8-internal.h` public header:

| Constant | Derived from |
| :------- | :----------- |
| `kTaggedSize` | `kApiTaggedSize` |
| `kJSMapTableOffset` | `kJSObjectHeaderSize` |
| `kOrderedHashMapHeaderSize` | `kFixedArrayHeaderSize` |

With static assertions against the V8 in SDK's native addon code it should fail
to compile a build that deviates from this schema.

The fourth, `record_slot_offset`, is the byte offset within the wrapper
`JSObject` of the slot holding the pointer to its record. That slot is internal
field 0: JavaScript objects can be allocated with space for internal fields,
which are typically used to hold pointers to native data structures. Unlike the
other three, it differs between V8 versions within the default build: it is 24
on Node.js 22 and 32 from Node.js 23 onward.

The writer publishes it in the thread-local struct rather than the schema fixing
it, because the writer can compute it from the V8 headers of the Node.js it is
compiled for: `kJSAPIObjectWithEmbedderSlotsHeaderSize` from Node.js 23,
`kJSObjectHeaderSize` for Node.js 22, plus
`kEmbedderDataSlotExternalPointerOffset` in either case. 

### Interaction with existing functionality

- **OTEP 4947 support.** Additive. This proposal defines a second value of
  `threadlocal.schema_version` and a second discovery walk; the record format
  and its parsing are shared. A profiler supporting both selects on
  `schema_version`.
- **OTEP 4719 support.** Unchanged: the same `threadlocal.*` keys OTEP 4947
  already established, carrying a new `threadlocal.schema_version` value.
- **`interpreter/nodev8`.** Independent. The V8 unwinder and this walk both read
  V8 objects from the same targets but share no state; a process can have
  either, both or neither. They are not gated on each other.
- **Trace types and enablement.** No new `InterpreterType` and no new
  `interpreterconfig` field. The `thread_context` switch that gates the existing
  walk gates this one too, as it gates a pseudo-interpreter that already
  contributes per-sample data rather than frames. With the switch on, a Node.js
  process that never installs the hook exports no `otel_thread_ctx_nodejs_v1`,
  so process initialization finds nothing and no walk is ever attempted:
  publishing nothing costs nothing.
- **OpenTelemetry SDKs.** Additive and optional. Nothing about existing Node.js
  SDK behaviour changes; a process that does not install the hook is
  indistinguishable from today.

## Trade-offs and mitigations

### Dependence on V8's internal object layout

The walk crosses `JSMap` and `OrderedHashMap`, neither of whose layouts is part
of V8's public API, and any of the offsets could change in a future V8.

**Mitigation:** the layout the reader assumes is pinned by `schema_version`, and
the writer's side of it is checked at build time rather than trusted: the SDK's
addon derives the same three fixed constants from the V8 headers it is compiled
against and static-asserts them, so a V8 this schema does not describe fails to
compile instead of yielding a process that publishes a contract a reader would
mis-walk. The one offset known to move within the supported range, the record
slot's, is published by the writer rather than fixed. A V8 that moves these
fields, or restructures them more deeply needs a new schema version. It is
possible to build versions of Node.js from source with non-default layouts using
certain build flags, e.g. enabling V8's pointer compression feature. We
explicitly do not support such builds with the current schema as it would result
in more complexity, and future support – should the need for it arise – would
need to introduce a new schema.

### Reader complexity relative to OTEP 4947

OTEP 4947's reader dereferences one thread-local to reach a record. This one
walks a hash map. That is more code, and it has to be defensive.

**Mitigation:** the identity hash narrows the search to one bucket, so the walk
is short in practice; and the two early exits mean the full walk only runs for
threads that actually have context attached. The complexity is confined to
reaching the record — everything from the record onward is shared with OTEP
4947. This repository already has code to read V8 heap objects out of target
memory in `interpreter/nodev8`.

### Mutation of the frame map while it is read

Since `AsyncContextFrame` is a JavaScript `Map`, one can rightly ask what
happens if it is read while it is being mutated.

Let's first see the scenarios where this can happen. Node.js treats frames as
immutable on most code paths. `enterWith` and `run` don't mutate the
`AsyncContextFrame`; they construct a new one that copies the current one and
then sets a new key-value pair in it. There is one mutating exception through
the public API: `AsyncLocalStorage.prototype.disable()` deletes its own entry
from the frame currently in the CPED slot, in place.
`Map.prototype.delete` writes hole sentinels over that entry's key and value and
adjusts the element and deleted-element counts.

It is also possible for third-party native addons to access the map through the
isolate's CPED getter method and then mutate it in place.

Both inserting and deleting can trigger a rehash, when the map grows or shrinks
more than a certain threshold. A rehash never exposes a half-built table:
`OrderedHashTable::Rehash` allocates a table with the new capacity, fills it
completely, and only then points the `JSMap` at it. A reader is therefore always
walking a table that is either the old one or the finished new one.

What a rehash _does_ do is destroy the old table as it copies out of it. Two
fields change:

- The bucket heads are overwritten, as the copy proceeds, with the indices of
  the entries that were deleted.
- The element count is overwritten, at the very end, with a tagged pointer to
  the new table.

(These serve to let an iterator that is live across the rehash and holds a
pointer to the old table to catch up: it follows the pointer to the new table,
and rewinds its cursor past the deleted entries that preceded its position.)

Both have consequences for a reader. A clobbered bucket head is simply a wrong
entry index: the walk follows it into the middle of some bucket's chain and
almost certainly does not find the entry keyed by the published
`AsyncLocalStorage` instance, so the sample misses. An element count holding a
pointer is observable only for the few instructions between that write and the
`JSMap` being pointed at the new table; a reader SHOULD check that the element
count is a Smi and bail out when it is not, which is what keeps it from reading
a pointer as a length. It could instead follow that pointer and redo the lookup
in the new table, but for a window this narrow it is not worth the extra
reader code.

### Garbage collection

In this section we discuss what can happen when the profiler does the walk
through the heap while V8 is performing garbage collection (GC) on it. GC is
special in that it moves objects around, so we want to examine it more closely.

The record itself is not a V8 heap object; it is malloc'd memory owned by the
wrapper, so it never moves as a result of GC. The objects on the path to reach
it (`AsyncContextFrame`, its backing table, the wrapper) on the other hand do
live in the V8 heap and can be moved by garbage collection.

When we say an object is moved during GC, it is in fact first copied into a new
location, and the old location is not freed until the last phase of the GC
cycle. The collectors write a forwarding pointer to the new copy of the object
in the header area of the source copy of the object, but otherwise don't mutate
the source's body. The walk never reads that header so to it an evacuated object
reads the same during GC.

Pointers to moved objects are updated non-atomically so the profiler can end up
walking a mixture of pointers to pre- and post-move addresses. This is
fortunately harmless; no JavaScript runs during the pause, so neither copy is
semantically mutated during the walk, and the profiler sees the same values
either way.

The old addresses are freed/reused only at the end of the GC cycle, but that
fortunately can not happen during a walk. OTEP 4947's signal-handler model
assumes the sampled thread is stopped, and GC is controlled by it. (Each isolate
has its own heap, collected by its own thread.) V8 does use parallel threads in
some cases to perform much of the copying, and those won't be stopped along with
the sampled thread. This is fortunately also not a concern since no memory is
freed until the sampled thread is resumed and ends the GC cycle.

The worst case scenario of GC interfering with a walk comes from the use of
parallel copying threads. With them, the new copy is not necessarily complete at
the moment it becomes reachable as various writes use relaxed ordering. The
consequence is the same one that the walk tolerates everywhere else: it reads
something that is not the key it is looking for, and the lookup misses.

### Sampling a thread that is not executing JavaScript

A thread can be sampled while no JavaScript is on its stack at all: an event
loop with nothing to do is parked in the libuv poll. Fortunately, this causes no
problems for the reader.

`cped_slot` addresses a field of the isolate rather than anything on the JS
stack, so the read itself is unaffected. In V8, threads need to "enter" an
isolate using an API before using them; fortunately in Node.js the threads enter
their isolate for the entire lifetime of the event loop so it's safe to read
from the isolates even when JavaScript code is not running.

Node.js and V8 mechanisms also ensure that an idle loop correctly does not
retain in the isolate's CPED slot the frame of the request that last ran but
rather it reverts to its top-level program value, which is normally
`undefined`.

This is also mostly a wall-clock concern. A thread parked in the poll consumes
no CPU and so is never sampled by a CPU-time profiler.


### Memory overhead

In the target: one record per live context, at most 640 bytes and typically 64,
plus one small JavaScript wrapper object and possibly some internal bookkeeping
of approximately 40 bytes. An SDK caching wrappers per span holds them for the
span's lifetime. The thread-local struct is four words per thread.

In the profiler: nothing per process beyond what OTEP 4947 already retains, and
no per-sample allocation the existing path does not already make.


# Alternatives Considered and Rejected

**Writing the OTEP 4947 thread-local on every attach/detach.** Rejected: an FFI
crossing per context transition, on Node.js's hottest path, paid whether or not
a reader exists. This is the option OTEP 4947 already declined for Node.js.

**A native-side map keyed by async ID.** The SDK could maintain its own native
structure mapping async IDs to records and publish a pointer to it. Rejected: it
reintroduces a native call per transition to keep the map current, and would
require extra bookkeeping.

**Publishing the record pointer in a JS-visible field instead of an internal
field.** Rejected: a JS-visible property is a tagged value subject to V8's
property-storage rules (in-object versus backing store, dictionary transitions),
so its location is neither stable nor cheaply computable by a reader. An
internal field is at a fixed offset and holds a raw aligned pointer.

**Resolving the V8 layout constants from `v8dbg_*` postmortem symbols instead of
fixing them in the schema.** This repository already does exactly that in
`interpreter/nodev8`, which reads V8 class and field offsets from the
`v8dbg_class_*` symbols Node.js builds export, so reusing that machinery is the
obvious thing to try. Rejected for two reasons. First, that metadata is
generated by V8's heuristic `gen-postmortem-metadata.py` and is known to be
incomplete and to lose symbols between releases — the existing `nodev8` code
documents this and carries fallbacks for it, which is tolerable for a
best-effort unwinder and not for a mechanism that must either be right or read
nothing. Second, there is nothing to discover: this schema version admits only a
default Node.js build, for which three of the values are constants that the SDK
static-asserts at compile time, and the fourth is published by the writer, which
knows it from the headers it was built against. Nothing prevents a future
implementation from using `v8dbg_*` as a *cross-check*, or as the mechanism by
which a later, parametrized schema version reaches non-default builds.

**Publishing the V8 layout constants as process context attributes.** An
earlier revision of this proposal did that: four `threadlocal.*` integers
carrying the tagged size and the three offsets, computed by the SDK's addon from
V8's public headers. Rejected: every Node.js release anyone deploys reports the
same four numbers, so the attributes bought no coverage while obliging both ends
of the contract to carry a layout-negotiation path that would essentially never
be exercised, and the profiler to treat every walk offset as a runtime value.
Fixing the values in the schema and bumping the version if a build ever needs
different ones keeps the common case simple and the uncommon one explicit.

The record slot offset is the exception, because it does differ across the
Node.js releases this schema covers. It is published, but in the thread-local
struct rather than as a process context attribute.

**Requiring the profiler to derive the layout from build flags.** Rejected: it
makes the profiler track V8's pointer-compression and sandbox configuration
matrix per Node.js release, for builds this schema version does not admit in the
first place.

# Author's Preferred Solution

The proposal above, as written. The alternatives are not really competing
designs for the same mechanism — each is a rejected variation on one step of
it — and the shape of the solution is largely forced: if native code must not
run on the context-switch path, then the runtime's own context-switching
mechanism has to be what carries the record, and something has to teach the
profiler to walk it.


# Testing Strategy

## Testing of Proposed Solution Itself

The walk is a pure function of target memory, which makes it unusually testable
for a mechanism of this kind.

- **Coredump tests.** This repository's `tools/coredump` suite already carries
  Node.js cases, and a coredump of a Node.js process with context attached gives
  a deterministic, checked-in regression test of the whole walk — TLS
  resolution, the `JSMap` lookup and record parsing — with no live process and
  no eBPF. This is the primary vehicle, and cases should cover: context
  attached, nothing attached (`undefined` in the slot), a torn-down isolate, a
  worker thread with its own isolate, and a record that has been invalidated.
- **Unit tests over synthesized memory.** The bucket walk, the identity-hash
  narrowing and the validation guards can be exercised against constructed
  `OrderedHashMap` images, including deliberately malformed ones (bucket count
  not a power of two, out-of-range entry indexes, `attrs-data-size` beyond the
  record) to confirm each is rejected rather than followed.
- **Integration tests.** `process/processcontext/integrationtests` establishes
  the pattern of a small target program publishing process context and the
  profiler asserting on what it reads; the equivalent here is a Node.js target
  running one of the reference writers. This is the only part of the strategy
  that needs a Node.js toolchain in CI, and it is the part that would catch a
  writer/reader disagreement that synthesized memory cannot.
- **Cross-version coverage.** Because the fixed layout constants are pinned by
  the schema rather than read from the target, a release that moves these fields
  is as much a risk as one whose `JSMap` structure changed — though the SDK's
  static assertions catch the former where it is built. Coredump cases from each
  supported major (22 with the flag, 24, and newer) are how that gets detected.
