# Probes

A probe is an OTel Collector extension that triggers stack collection from an
eBPF program and reports the result through the profiler. It reuses the
unwinders, symbolization and OTLP export of the profiler and defines its own
sample type. See the [Probe API](https://pkg.go.dev/go.opentelemetry.io/ebpf-profiler/tracer#Probe)
for the interface.

Most probes are expected to live in their own repository. A probe built
against the public API in package `tracer` works the same in or out of tree,
and an out of tree probe does not depend on the review capacity of this
project.

## In-tree probes

Every probe in this repository is carried by the maintainers through every
change to the tracer. A probe is accepted only when that cost is justified.

- The data answers a question that many users of the profiler have. A probe
  tied to one application, library version or vendor belongs out of tree.
- The data cannot be produced with the generic `kprobe` or `uprobe` probes,
  and no existing probe can be extended to produce it.
- Sample types follow the OTel Profiles data model and reuse names and units
  already in use where they fit. When the probe samples, the reported values
  allow the full population to be estimated.
- The attach points are stable across the supported kernels. Tracepoints are
  preferred over kprobes where one exists.
- The cost per event is bounded. High frequency events are filtered or sampled
  in eBPF before stack unwinding, and the rate is configurable.
- Probe programs are part of the embedded eBPF ELF and must not raise the
  complexity or the size of the programs shared with the tracer.
- At least one [code owner](../CONTRIBUTING.md#becoming-a-code-owner) in
  [CODEOWNERS](../.github/CODEOWNERS) maintains the probe. A probe that loses
  its owners or stops working on supported kernels may be removed.

## Proposing a probe

Open an issue that describes the data the probe collects, who uses it and why
the generic probes do not cover it. This settles whether the probe belongs in
tree before code is written. Starting out of tree is a good way to prove the
probe, and a probe with users is easier to accept.

## External probes

Probes maintained outside this repository. Open a pull request to add yours.

| Probe | Description |
|-------|-------------|
| [memcache-probe](https://github.com/florianl/memcache-probe) | Stack traces at hardware cache events such as L1 data cache or last level cache misses. |
