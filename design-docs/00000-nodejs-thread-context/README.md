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

- `process/processcontext` reads OTEP 4719 process context and gates
  thread-context support on `threadlocal.schema_version` matching
  `tlsdesc_v1_dev`.
- `interpreter/threadcontext` locates the `otel_thread_ctx_v1` thread-local
  across the TLS access models a target may have been built with (TLSDESC,
  legacy GNU global-dynamic, linker-relaxed initial-exec and local-exec) and
  decodes the record. **Nearly all of this is reusable as-is**: what this
  proposal changes is the size and interpretation of what the thread-local
  holds, not how it is found.
- `interpreter/nodev8` already unwinds V8 JavaScript stacks, which means the
  profiler already reads tagged V8 words and V8 heap object fields out of
  target memory. The walk proposed here needs the same primitives.
- `design-docs/00002-custom-labels` is the sibling mechanism for Go pprof
  labels, which also has a unit of context other than the OS thread.

### How Node.js tracks the active continuation

What has to be tracked in Node.js is the active *continuation* on a thread.
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

As called out in OTEP 4947, this combination of constant switching and the high
cost of running code at each switch means an implementation of that spec would
not be efficient for current versions of Node.js. As a consequence, Node.js
remains one of the few runtimes for which the profiler already ships an unwinder
(`interpreter/nodev8`) but would still have no way to attribute a sample to a
trace even if an OTEP 4947 thread-context reader for its default schema ships.

Thus, similarly to how Go is already supported under its own schema version, we
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
- **Changing the record format.** Any change there belongs in OTEP 4947.

# Proposed Solution

## The walk, in outline

"The SDK" below is shorthand for whichever component in the target publishes the
context — an OpenTelemetry SDK, a vendor tracer, or any other Node.js tracing
code. Such a component publishes context by:

1. Creating one `AsyncLocalStorage` instance per isolate, and telling its native
   addon about it.
2. Allocating a **Thread-Local Context Record** (OTEP 4947's format, unchanged)
   behind a JavaScript wrapper object for every tracing span, and storing a raw
   pointer to the record in the wrapper's internal field.
3. Attaching context by storing that wrapper in the `AsyncLocalStorage` (and
   detaching it by storing `undefined`). Both are pure-JavaScript operations; no
   native code runs for them.

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
`threadlocal.schema_version`, and otherwise adds four more process attributes.

Reused from OTEP 4947:

- `threadlocal.schema_version` — `nodejs_v1_dev` for experimentation, to become
  `nodejs_v1` once stabilized. Recognizing this value is what tells the profiler
  to use the walk described here instead of OTEP 4947's TLS-pointer walk.
- `threadlocal.attribute_key_map` — unchanged, including its append-only
  semantics.

The four added attributes are all V8 layout constants captured from the V8
headers the target's addon was compiled against, so that the profiler does not
have to derive them from the target's pointer-compression and sandbox build
flags, nor look up V8 internal symbols:

| Key | Meaning |
| :-- | :------ |
| `threadlocal.js_object_record_offset` | Byte offset, within the wrapper JSObject, of the slot holding the pointer to its record. That slot is internal field 0: JavaScript objects can be allocated with space for internal fields, which are typically used to hold pointers to native data structures. |
| `threadlocal.tagged_size` | V8's tagged-pointer width in bytes: 4 with pointer compression, 8 without. |
| `threadlocal.js_map_table_offset` | Byte offset, within a V8 `JSMap`, of the tagged pointer to its backing `OrderedHashMap` table. |
| `threadlocal.ordered_hash_map_header_size` | Size of the `OrderedHashMap` header preceding its element-count fields. |

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

key: "threadlocal.js_object_record_offset"
value:
  int_value: 24

key: "threadlocal.tagged_size"
value:
  int_value: 8

key: "threadlocal.js_map_table_offset"
value:
  int_value: 24

key: "threadlocal.ordered_hash_map_header_size"
value:
  int_value: 16
```

> **Note:** As in OTEP 4947, the `threadlocal.*` keys are inter-process
> coordination metadata rather than telemetry attributes, and are not expected
> to appear in OTLP exports.

The last three values are properties of the V8 build and not of the SDK; they
are published rather than hardcoded in the profiler because they vary with build
configuration, and because two of them (`js_map_table_offset`,
`ordered_hash_map_header_size`) are not exposed by V8's public headers and so
cannot be discovered by a reader at all without either this contract or its own
symbol archaeology. See "Alternatives Considered" for why they are not taken
from V8's `v8dbg_*` postmortem symbols, which this repository already consumes
elsewhere.

### Thread-local variable

A single thread-local, `otel_thread_ctx_nodejs_v1`, is exported as an ELF TLS
symbol in the dynamic symbol table, providing the information specific to the
Node.js runtime needed to find the OTEP-4947 record. It is a struct, not a
pointer:

| Name | Offset | Data type | Notes |
| :--- | :----- | :-------- | :---- |
| `cped_slot` | `0` | pointer | Address of this thread's isolate's `ContinuationPreservedEmbedderData` slot. The slot holds a tagged V8 word; dereferencing it yields the active Node.js `AsyncContextFrame`. Lets the profiler reach the active frame without any V8 internal symbol lookup. Doubles as the **gate**: an all-zero value means the SDK has not published on this thread, has torn it down again, or has closed the gate temporarily, and no other field may be used while it reads zero. |
| `als_handle` | `sizeof(void *)` | pointer | A `v8::Global<Object>` referring to the published `AsyncLocalStorage` instance in this thread's isolate. Its representation is a single V8 internal pointer; dereference it to obtain the instance's tagged address, which is the key to look up in the frame. |
| `als_identity_hash` | `2 * sizeof(void *)` | int32, followed by 4 bytes of padding | The JS identity hash of that instance, so the profiler can restrict its search to one hash bucket rather than scanning every entry. |
| `undefined_addr` | `3 * sizeof(void *)` | tagged word | This thread's isolate's tagged address of the `undefined` singleton. Lets the profiler detect "no context attached" by comparison, rather than by structurally validating whatever the frame maps our key to. |

All four fields are fixed while the isolate lives, but they are not written only
once: the SDK populates them when it installs its hook and zeroes them again at
teardown.

Additionally, a writer MAY temporarily set the `cped_slot` to zero and later
restore its previous value if it wishes to prevent reads for a period of time
because some condition makes the walk unsafe — see "Garbage collection" for a
motivating example.

The profiler MUST therefore re-read at least the `cped_slot` each time it
samples the thread, and MUST NOT substitute cached values for other fields when
it changes. That costs one read of four words, which is negligible beside the
walk it precedes. A reader using a stale value of `cped_slot` after it changed
could go on walking a dead isolate's `cped_slot`. The profiler also MUST NOT
infer from a zero reading that a thread is permanently uninstrumented.

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

Because the contract is byte-level, "zeroed" means an all-zero representation.
A C++ writer assigning a null pointer to `cped_slot` produces that on the ELF
platforms in scope, the same assumption OTEP 4947 already relies on; a writer on
any platform where a null pointer is not all-zero bits MUST zero the bytes
explicitly.

### Thread-local context record

Unchanged from OTEP 4947, including field offsets, `attrs-data` encoding, the
`valid` byte, the 2-byte alignment requirement, the last-occurrence-wins rule
for repeated key indexes, and the recommendation to keep the total record at or
under 640 bytes. The profiler MUST be able to use the same parser for both
schemas.

### Publication protocol

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

Step 3 is the only step on the hot path when a wrapper is reused, which is the
intended pattern: an SDK SHOULD cache the record and its wrapper created in
steps 1 and 2 on the span or equivalent object so that re-entering a context
allocates nothing and calls no native code.

The record's lifetime SHOULD be tied to the wrapper's, so that a record stays
alive exactly as long as the wrapper is reachable in the JavaScript heap and can
thus still be presented to a reader. The record should be released when the
wrapper is known to be unreachable. (This is typically achieved using V8 Globals
as weak references to wrappers with garbage collection callbacks.)

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

A memory-optimizing implementation can initially allocate a small record with
space for only a few small attributes, and have a mechanism to grow it if
needed.

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
It SHOULD additionally clear internal field 0 of all live wrappers known to it
and release the memory these fields point to, holding the records.

Clearing wrapper internal fields and releasing the records' memory is
proportional to the number of live wrappers and requires the SDK to track them
all; it is defense in depth, and is redundant once the thread-local is cleared,
since a reader that stops at `cped_slot == 0` never reaches a wrapper.

Neither omission can crash the profiler, as reading freed or unmapped memory in
another process fails or returns garbage rather than faulting the reader. The
risk is misattribution instead: a stale walk through a dangling `cped_slot` can
still *succeed* and attach a fabricated trace ID to a genuine sample, which is
why the record validation in "Thread sampling" is not optional.

### Runtime requirements

The mechanism requires `AsyncLocalStorage` to be backed by `AsyncContextFrame`,
since that is what puts the store map into the CPED slot. In Node.js this is
available from 22.7.0 behind `--experimental-async-context-frame`, and on by
default from Node 24, where it can still be turned off with
`--no-async-context-frame`.

An SDK MUST feature-detect this rather than infer it from the version and
command line, which disagree in both directions: `NODE_OPTIONS` can enable or
disable it without appearing in `process.execArgv`, and worker threads may be
created with a different `execArgv` than the main thread. Inferring "on" when it
is off is the dangerous direction — the SDK keeps working from JavaScript's
point of view while the CPED slot is never written, so the profiler sees a
record that nothing updates. A direct probe (asking native code what is in the
CPED slot during a `run()`) tests the exact slot readers depend on.

An SDK that cannot satisfy the requirement MUST NOT publish
`threadlocal.schema_version`.

## Changes in the profiler

### Where this hooks in

The proposal is additive at three points, in increasing order of new code:

1. **`process/processcontext`** — accept `nodejs_v1_dev` (and later `nodejs_v1`)
   alongside `tlsdesc_v1_dev` as a supported `threadlocal.schema_version`, and
   parse the four integer V8 layout attributes. The `attribute_key_map` handling
   is untouched. The schema version must be carried forward so the sampling path
   can select a walk; today a single supported value means it need not be.
2. **`interpreter/threadcontext`** — a second TLS export name,
   `otel_thread_ctx_nodejs_v1`, and a 4-word struct where the existing schema
   has a single 8-byte pointer. The TLS access-model resolution, the symbol and
   relocation matching, and the `TLSVarInfo` plumbing shared with `apmint` are
   reused unchanged: locating a thread-local is the same problem regardless of
   what it holds.
3. **The walk itself** — new code, reading V8 heap objects out of target memory.
   `interpreter/nodev8` establishes the primitives (tagged word handling,
   bounded remote reads of V8 objects) but this walk is independent of stack
   unwinding and should not be entangled with the unwinder's state.

An open implementation question is whether the walk lives in
`interpreter/threadcontext` behind a per-schema strategy, or in its own package
that `threadcontext` delegates to. The former keeps one entry point for "read
this thread's context"; the latter keeps V8 knowledge out of a package that is
otherwise runtime-agnostic. This document does not decide it.

### 1. Process initialization

Unchanged from OTEP 4947's process-initialization steps, except that the
profiler looks for `otel_thread_ctx_nodejs_v1` in the dynamic symbol tables, and
treats a `threadlocal.schema_version` of `nodejs_v1` or `nodejs_v1_dev` as
selecting this walk. The profiler MUST also read the four V8 layout constants
before sampling; they are not optional for this schema, and a target that
declares either schema version without them SHOULD be treated as having
incomplete process context, to be re-read on the next update.

### 2. Thread sampling

As in OTEP 4947, the profiler MUST only read while the target thread is stopped
or interrupted.

The pseudo-code below assumes a 64-bit build with pointer compression and the V8
sandbox both off, which is true of Node's bundled V8 in the versions this
mechanism supports. Tagged pointers have their low bit set; clear it to get the
object address.

```cpp
auto* ctx = read_tls<otel_thread_ctx_nodejs_v1_t>();
if (ctx->cped_slot == 0) return NO_CONTEXT;  // nothing published here
// No async-context frame is active.
if (*ctx->cped_slot == ctx->undefined_addr) return NO_CONTEXT;

// CPED -> active AsyncContextFrame (a JS Map) -> its backing OrderedHashMap.
auto* acf = untag<JSMap>(*ctx->cped_slot);
auto* table = untag<OrderedHashMap>(
    *(tagged_ptr*)((char*)acf + js_map_table_offset));

// Find the entry keyed by our AsyncLocalStorage instance. A reader uses the
// published identity hash to walk a single bucket. Bucket and entry layout
// follow from ordered_hash_map_header_size and tagged_size.
uintptr_t als = *ctx->als_handle;
Entry* e = find_entry(table, als, ctx->als_identity_hash);
if (!e) return NO_CONTEXT;  // not in this frame
if (e->value == ctx->undefined_addr) return NO_CONTEXT;  // explicitly detached

// The value is the wrapper JSObject; internal field 0 holds the record pointer.
auto* wrapper = untag<JSObject>(e->value);
auto* record =
    *(OtelThreadCtxRecord**)((char*)wrapper + js_object_record_offset);
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
pointer walk yields garbage at the same offsets. Checking `valid == 1` is the
minimum; sanity-checking `attrs-data-size` as well as the `OrderedHashMap`
bucket count being a power of two are cheap additional guards. Every remote read
on the walk is bounded and failure-tolerant, so a target that is mid-teardown or
built differently than advertised costs a dropped context rather than a bad one.

### Interaction with existing functionality

- **OTEP 4947 support.** Additive. This proposal defines a second value of
  `threadlocal.schema_version` and a second discovery walk; the record format
  and its parsing are shared. A profiler supporting both selects on
  `schema_version`.
- **OTEP 4719 support.** Additive, in the manner OTEP 4947 already established:
  four more `threadlocal.*` keys in `ProcessContext.attributes`.
- **`interpreter/nodev8`.** Independent. The V8 unwinder and this walk both read
  V8 objects from the same targets but share no state; a process can have
  either, both or neither. They are not gated on each other.
- **Trace types and enablement.** As with custom labels, this rides the
  thread-context trace type rather than introducing its own; a target that
  publishes nothing costs nothing.
- **OpenTelemetry SDKs.** Additive and optional. Nothing about existing Node.js
  SDK behaviour changes; a process that does not install the hook is
  indistinguishable from today.

## Trade-offs and mitigations

### Dependence on V8's internal object layout

The walk crosses `JSMap` and `OrderedHashMap`, neither of whose layouts is part
of V8's public API, and any of the offsets could change in a future V8.

**Mitigation:** the offsets are not hardcoded in the profiler. They are captured
at addon-compile time from the very V8 headers the addon is built against and
published through the process context, so the profiler is told the layout of the
V8 it is actually looking at. This does not protect against V8 restructuring
these objects more deeply than an offset change, which is what the versioned
`schema_version` is for. It does mean that the usual failure mode — a Node.js
release built with different pointer-compression or sandbox settings — is
handled without profiler changes.

### Reader complexity relative to OTEP 4947

OTEP 4947's reader dereferences one thread-local to reach a record. This one
walks a hash map. That is more code, and it has to be defensive.

**Mitigation:** the identity hash narrows the search to one bucket, so the walk
is short in practice; and the two early exits mean the full walk only runs for
threads that actually have context attached. The complexity is confined to
reaching the record — everything from the record onward is shared with OTEP
4947. This repository already has code to read V8 heap objects out of target 
memory in `interpreter/nodev8`.

### Rehashing of the map

Since `AsyncContextFrame` is a JavaScript `Map`, one can rightly ask what would
happen if it were mutated in place and triggered a rehash while it is being
read. Fortunately, the way it is currently implemented in Node.js is that
existing maps are never mutated; they are copied on writes.

### Garbage collection

The objects on the walk (`AsyncContextFrame`, its backing table, the wrapper)
live in the V8 heap and can be moved by a garbage collection. OTEP 4947's
signal-handler model assumes the sampled thread is stopped, which prevents the
writer from racing the reader — but it does not by itself establish that no
*other* thread can relocate the objects being walked while the sampled thread is
stopped.

In practice, V8 performs object motion during the atomic pause on the isolate's
own thread, which is the stopped thread; concurrent GC threads mark rather than
move. We believe this makes the walk safe under the same assumptions OTEP 4947
already makes.

Note that the record itself is not a V8 heap object; it is malloc'd memory owned
by the wrapper, so it never moves as a result of GC. Only the path to it
involves heap objects.

Should that walk prove unsafe, a writer MAY close the gate for the duration of a
collection: register GC prologue and epilogue callbacks on the isolate, zero
`cped_slot` in the prologue and restore it in the epilogue, with the same
compiler fence and volatile store the other gate writes use. The profiler needs
no change at all, as it already stops at a zero gate and is forbidden from
treating it as permanent.

Losing the trace context for GC samples is a design decision. A collection is
triggered by whole-heap pressure that the active request may have contributed
little to, so attributing that time to whichever context happened to be current
would manufacture a plausible-looking but ultimately wrong attribution.

### Sampling a thread that is not executing JavaScript

A thread can be sampled while no JavaScript is on its stack at all: an event
loop with nothing to do is parked in the libuv poll. `cped_slot` addresses a
field of the isolate rather than anything on the JS stack, so the read itself is
unaffected. Node keeps an isolate entered for the whole lifetime of the event
loop it serves, both on the main thread and in worker threads, so the
not-entered state barely arises while an application is running. The only loop
that does spin with no isolate entered is the one a worker runs while it waits
for the platform to release its isolate during teardown, by which point the gate
is already closed.

When the loop is idle, the CPED slot holds whatever frame was current at the
outermost level. Node unwinds the slot as the stack unwinds; every entry into
JavaScript goes through `InternalCallbackScope`, which exchanges the frame on
entry and restores the prior one on scope exit. Tick, timer and promise runners
do the same explicitly. Thus, an idle loop correctly does not retain the frame
of the request that last ran. It normally exposes `undefined`, which the
profiler rejects by comparison against `undefined_addr`. The exception would be
a context installed with `enterWith` at the outermost level of the JavaScript
program and never cleared, which does persist. This is not a common practice,
and if it occurs, it could rightfully be considered the top-level context of the
program.

This is also mostly a wall-clock concern. A thread parked in the poll consumes
no CPU and so is never sampled by a CPU-time profiler.

We do not ask targets to publish an "executing JavaScript" flag. The profiler
can already walk the target's stack and so can tell a thread parked in the poll
from one that is running, which is all such a flag would say; and maintaining it
would mean marking entry to and exit from JavaScript in the target, which is
per-call work on the hottest path this design exists to keep native code off.

### Memory overhead

In the target: one record per live context, at most 640 bytes and typically 64,
plus one small JavaScript wrapper object and possibly some internal bookkeeping
of approximately 40 bytes. An SDK caching wrappers per span holds them for the
span's lifetime. The thread-local struct is four words per thread.

In the profiler: four integers per process beyond what OTEP 4947 already
retains, and no per-sample allocation the existing path does not already make.

### Trace sampling

Unchanged from OTEP 4947: an out-of-process reader cannot influence in-process
sampling decisions, so samples may reference traces the SDK never exported. The
same mitigation applies — publish the attributes that matter directly in
`attrs-data` via `attribute_key_map`.

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
publishing them.** This repository already does exactly that in
`interpreter/nodev8`, which reads V8 class and field offsets from the
`v8dbg_class_*` symbols Node.js builds export, so reusing that machinery is the
obvious thing to try. Rejected for three reasons. First, that metadata is
generated by V8's heuristic `gen-postmortem-metadata.py` and is known to be
incomplete and to lose symbols between releases — the existing `nodev8` code
documents this and carries fallbacks for it, which is tolerable for a
best-effort unwinder and not for a mechanism that must either be right or
publish nothing. Second, `js_object_record_offset` is not a property of the V8
build at all: it depends on how the wrapper object was allocated by the addon,
so no V8 symbol can supply it. Third, the publishing target has the offsets
exactly, at compile time, from the headers it was built against; asking the
profiler to rediscover what the writer already knows adds a failure mode for no
gain. Nothing prevents a future implementation from using `v8dbg_*` as a
*cross-check*.

**Requiring the profiler to derive the layout from build flags.** Rejected: it
makes the profiler track V8's pointer-compression and sandbox configuration
matrix per Node.js release, and two of the four offsets are not derivable from
public headers at any rate.

# Author's Preferred Solution

The proposal above, as written. The alternatives are not really competing
designs for the same mechanism — each is a rejected variation on one step of
it — and the shape of the solution is largely forced: if native code must not
run on the context-switch path, then the runtime's own context-switching
mechanism has to be what carries the record, and something has to teach the
profiler to walk it.

The genuinely open choices are smaller and called out where they arise: whether
the walk lives inside `interpreter/threadcontext` or in a package of its own,
and whether to add a `v8dbg_*` cross-check of the published offsets. Both can be
settled during implementation without revisiting this document.

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
- **Cross-version coverage.** Because the layout constants come from the target,
  the risk is a Node.js release whose `JSMap` structure changed rather than
  moved. Coredump cases from each supported major (22 with the flag, 24, and
  newer) are how that gets detected.

## Impact on Testing of Other Systems/Components

Minimal. The change to `process/processcontext` is an additional accepted schema
version and four more parsed attributes, both covered by its existing
table-driven tests. `interpreter/threadcontext` gains a second export name and
struct shape; its TLS-resolution tests are unaffected because that layer does
not interpret the bytes it locates. Nothing in `interpreter/nodev8` changes, so
the existing V8 unwinder tests and coredump cases are untouched.

The one thing that becomes harder is testing the two mechanisms in combination:
a target publishing both schema versions is not meaningful, but a host running
Node.js and non-Node.js instrumented processes side by side is, and the
schema-version selection deserves a test at that level.

# Future Possibilities

- **Other runtimes with the same shape.** The pattern — publish a discovery
  struct once, let the runtime do the context switching, teach the reader to
  walk runtime internals — should transfer to other managed runtimes whose
  context model is not the OS thread.
- **Sharing the V8 layout constants.** If the constants outgrow this mechanism,
  they could be promoted out of `threadlocal.*` and reused by any reader that
  needs to walk a V8 heap, including `interpreter/nodev8`.
- **libuv thread pool attribution.** Out of scope here because Node.js offers no
  mechanism to carry a record onto a pool thread. Those threads would in fact
  suit OTEP 4947's original design well, since each runs one work item at a
  time; if Node.js ever grows a way to associate context with submitted work,
  this becomes worth revisiting.
- **Non-Linux platforms.** As with OTEPs 4719 and 4947, the discovery contract
  here is ELF/TLSDESC-based. The record format and the CPED walk are not
  Linux-specific; only the mechanism for finding the discovery struct is.

# Decision

TBD.
