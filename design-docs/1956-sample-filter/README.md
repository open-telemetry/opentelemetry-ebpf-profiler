Sample Filter Extension
=======================

# Meta

- **Author(s)**: ms-hujia
- **Start Date**: 2026-10-24
- **Goal End Date**: TBD
- **Primary Reviewers**: TBD

# Problem

Profiling every process on nodes with many JVM or Python services is costly:
interpreter symbolization reads remote memory, and per-executable eBPF maps grow
with every discovered binary. Operators want to exclude irrelevant workloads, but
the criteria (image, labels, workload name) live outside the profiler.
See #1956 and #1891.

# Success Criteria

- No extension code runs on the per-sample hot path, and no sample waits for it.
- Unconfigured, behavior is unchanged (one nil check).
- The performance impact on the per-sample hot path is lower than 5%.
- Unknown processes and races have defined, documented behavior.
- Extensions stay small; common ones are shared.

## Scope

Not in scope: faster interpreter memory access (separate work), unloading maps
already loaded when a skip arrives late, binding several filter extensions
directly, and attach-time gating (follow-up).

# Proposed Solution

## Flow

Dotted arrows are queued and asynchronous; solid arrows are direct calls.
`key` is `(containerID, pid)`. "Source" is whatever the extension consults (for
example `k8s_observer`).

```
  Tracer            ProcMgr           Worker           Extension        Source
     |                 |                 |                 |               |
     |---- new pid --->|                 |                 |               |
     |                 |. queue Attach .>|                 |               |
     |--- sample #1 -->|                 |                 |               |
     |                 | miss: default   |                 |               |
     |                 |                 |.. OnAttach(p) .>|               |
     |                 |                 |                 |. lookup(cid) >|
     |                 |                 |                 |<image, labels |
     |                 |                 |< Set(key,Skip) .|               |
     |                 |                 | apply batch     |               |
     |--- sample #N -->|                 |                 |               |
     |                 | hit: Skip, drop |                 |               |
     |--- pid exits -->|                 |                 |               |
     |                 |.. queue Stop ..>|                 |               |
     |                 |                 |.. OnStop(key) .>|               |
     |                 |                 | evict entry     |               |
```

## Types

Package `samplefilter`, a leaf package with no profiler dependencies.

```go
// Decision is the verdict applied to a sample.
type Decision uint8

const (
	Keep Decision = iota // zero value: process and report the sample
	Skip                 // drop the sample before any interpreter or symbolization work
)

func (d Decision) String() string                   // "keep" or "skip"
func (d *Decision) UnmarshalText(text []byte) error // case-insensitive; error otherwise

// Process is read-only; callbacks must not modify it or its maps.
type Process struct {
	PID         uint32            // host PID
	ContainerID string            // bare ID parsed from cgroup; "" means an OS process
	Executable  string            // /proc/PID/exe target, " (deleted)" stripped
	Comm        string            // /proc/PID/comm, read at attach (new)
	Env         map[string]string // only variables listed in include_env_vars; may be nil
	ExtraMeta   map[string]string // from configured MetaEnrichers; may be nil
}
```

Receiver config, in `collector/config`. Defaults are proposed.

```go
type Config struct {
	Extension       component.ID  `mapstructure:"extension"`        // required
	DefaultDecision Decision      `mapstructure:"default_decision"` // default keep
	UpdateInterval  time.Duration `mapstructure:"update_interval"`  // default 15s, > 0
	QueueSize       int           `mapstructure:"queue_size"`       // per queue, default 4096
	NotifyRate      int           `mapstructure:"notify_rate"`      // callbacks/s, default 500
}
```

```yaml
receivers:
  ebpf_profiler:
    sample_filter:
      extension: image_filter
      default_decision: keep
      update_interval: 15s
```

## Interfaces

Every method takes `pid` and `containerID` together; the pair is the key. An empty
`containerID` denotes an OS (non-container) process.

```go
// Filter is implemented by the extension. Callbacks run on the worker goroutine
// only, one at a time, in per-key order. They return nothing and must return
// quickly: do I/O in the extension's own goroutines.
type Filter interface {
	// Register is called once before any callback. m stays valid until
	// Shutdown. A non-nil error aborts receiver start, subject to error_mode.
	Register(m Map) error
	// OnAttach: a process was discovered; existing ones are replayed after Register.
	OnAttach(p Process)
	// OnUpdate: the process metadata changed, for example after exec.
	OnUpdate(p Process)
	// OnStop: the process exited; the profiler evicts its entry itself.
	OnStop(pid uint32, containerID string)
}

// Map records decisions. Methods return nothing, never block, and are safe for
// concurrent use. Updates are queued and applied at the next update round; if
// the queue is full the oldest pending update is dropped and counted.
type Map interface {
	// Set records d for the key, replacing any earlier decision.
	Set(pid uint32, containerID string, d Decision)
	// Delete removes the key's decision; later samples use default_decision.
	Delete(pid uint32, containerID string)
}

// In package collector: what an OTel extension implements to be bound.
type SampleFilterExtension interface {
	extension.Extension // Start(ctx, host) error; Shutdown(ctx) error
	samplefilter.Filter
}
```

## Decision map

Profiler-internal, keyed by `(containerID, pid)`, written only by the worker and
read lock-free on the hot path:

```go
// lookup returns the decision for a sample; found is false if the key is absent.
func (m *decisionMap) lookup(pid uint32, containerID string) (d Decision, found bool)
```

## Sample path

Each sample does one non-blocking `lookup`. If found it applies the decision;
otherwise it uses `default_decision`. It never waits for the extension and never
buffers. A late decision takes effect from the next update round, at most
`update_interval` (15s by default) later.

## Worker

One separate goroutine does two jobs. `SynchronizeProcess` and the exit path only
enqueue events, so neither process attach nor the first sample waits.

1. **Notify**: delivers events through a bounded, rate-limited queue. Each
   `(containerID, pid)` has its own logical pipe: its events are ordered and
   coalesced, and different keys are independent. Pending events of one key:

   | Pending | New | Result |
   |---|---|---|
   | Attach | Update | Attach with the newer `Process` |
   | Attach | Stop | both dropped; the extension never saw the key |
   | Update | Update | the latest Update |
   | Update | Stop | Stop |

   A Stop followed by an Attach for the same key stays in order.
2. **Apply**: every `update_interval` the pending `Map` updates are applied as one
   batch; the latest update per key wins.

Overflow in either queue is counted in a metric.

## Races

| Case | Behavior |
|---|---|
| New key, first samples | default decision |
| Late decision | applied at the next update round |
| PID reuse, same container | `OnStop` eviction, event order preserved |
| PID reuse, other container | a different key; the old entry never applies |
| Decision flips | applies from the next round |
| Dropped event | coalescing plus metric |

## Observability

Metrics: time from attach to first decision, keys still without a decision, and
dropped or coalesced events. There is no decision timeout; a slow extension is
visible through these metrics instead.

## Writing an extension

An extension keeps the `Map` from `Register` and turns process metadata into
`Set` and `Delete` calls.

**A. The metadata is enough** (executable, comm, container ID, env). The extension
is a pure function: `OnAttach` and `OnUpdate` evaluate rules and call `Set`;
`OnStop` needs nothing because the profiler evicts the entry. Examples: skip
`*/envoy` or `*/istio-proxy`, skip by comm, honor an env opt-out, or profile only
an executable allowlist.

**B. Extra information is needed.** The extension keeps its own cache, fed by an
external source, and joins on container ID, the one key part the metadata always
carries:

1. `OnAttach` looks up the cache; on a hit it calls `Set`.
2. On a miss it records `container -> pending pids` and returns immediately.
3. When the source delivers data (watch event, API call) it calls `Set` for each
   pending `(pid, containerID)`. `OnStop` removes the pid from its index.

Until the answer arrives the default applies; afterwards the decision lands at the
next update round. Examples: image, namespace, labels and owner kind from
`k8s_observer`; an operator-managed allowlist over HTTP; team or tier from a
service catalog. Kubernetes container IDs carry a `containerd://` prefix that must
be stripped.

## Extensions to contribute

The receiver ships only the interface and the map. Reference extensions will be
contributed later as separate components, following the pattern of the observers
in opentelemetry-collector-contrib:

1. `static_rules`: category A; globs on the executable name or path only.
2. `k8s_filter`: image, namespace, label and annotation rules on `k8s_observer`.
3. `container_allowlist_api`: HTTP add/remove of container IDs behind `confighttp`
   auth, for on-demand profiling during incidents.
4. `docker_filter` / `ecs_filter`: the same as `k8s_filter` for non-Kubernetes
   hosts, using the contrib docker and ECS observers.
5. `combine_filter`: an example of composing filters. Since only one extension is
   bound, it is itself a `Filter` that wraps several others and combines their
   decisions with an `or` / `and` operand: `or` skips if any child says `Skip`,
   `and` skips only if every child says `Skip`.

   Why: baseline plus on-demand. A node should always profile the payments service,
   selected by image (`k8s_filter`), and during an incident also profile whichever
   other container an SRE adds through `container_allowlist_api`, with no restart
   or config change. Neither filter does both alone. With `and`, a sample is
   skipped only if both filters skip it, so a container is profiled if it runs the
   payments image or is allowlisted. Use `or` to stack exclusions instead, for
   example the image rule plus a `static_rules` entry that skips a log shipper
   bundled in the same container.

   How: the user wants the payments service always profiled and any other
   container profiled on demand. They configure both filters and combine them with
   `and`:

   ```yaml
   extensions:
     container_allowlist_api:
       endpoint: 127.0.0.1:9911      # PUT/DELETE /containers/{id}
     k8s_filter/payments_image:
       images: ["registry.example.com/payments/api:*"]   # skip everything else
     combine_filter:
       operator: and                 # or | and
       filters: [container_allowlist_api, k8s_filter/payments_image]
   receivers:
     ebpf_profiler:
       sample_filter:
         extension: combine_filter
   ```

   Then, day to day:
   1. Nothing to do: only containers running the payments image are profiled.
   2. During an incident, add the suspect container:
      `curl -X PUT 127.0.0.1:9911/containers/<container-id>`. It is profiled from
      the next update round, at most `update_interval` later (15s by default).
   3. When done, remove it with `curl -X DELETE` on the same URL; it goes back to
      being skipped, and the payments service is unaffected throughout.
