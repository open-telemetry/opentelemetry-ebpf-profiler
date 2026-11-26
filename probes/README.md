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
- The attach points are stable across the supported kernels and
  architectures. Tracepoints are preferred over kprobes where one exists.
- The cost per event is bounded. High frequency events are filtered or sampled
  in eBPF before stack unwinding, and the rate is configurable.
- Probe programs are part of the embedded eBPF ELF and must not raise the
  complexity or the size of the programs shared with the tracer.
- An approver or maintainer of this project sponsors the probe and agrees to
  review it.
- The author becomes a [code owner](../CONTRIBUTING.md#becoming-a-code-owner)
  of the probe in [CODEOWNERS](../.github/CODEOWNERS) and is responsible for
  it. A probe that loses its owners or stops working on supported kernels may
  be removed.

## Proposing a probe

Open an issue before code is written. This settles whether the probe belongs
in tree and is the place to find a sponsor. The issue names

- the code owners of the probe.
- similar probes, in or out of tree, and why neither they nor the generic
  probes cover the use case.
- the data the probe collects, the sample types it reports and who uses it.
- the configuration options of the probe.

Starting out of tree is a good way to prove the probe, and a probe with users
is easier to accept.

## Donating a probe

Once the issue is accepted, the probe goes through the normal review and may
need changes to match the conventions of this repository. The pull request adds

- the probe under `probes/<name>`, following the layout of the existing probes.
- a `README.md` for the probe that states its purpose, documents its
  configuration with an example and lists the sample types it reports.
- tests and CI coverage, as for any other change.
- an entry in [CODEOWNERS](../.github/CODEOWNERS) for the probe directory.

## External probes

Probes maintained outside this repository. Open a pull request to add yours.

| Probe | Description |
|-------|-------------|
| [memcache-probe](https://github.com/florianl/memcache-probe) | Stack traces at hardware cache events such as L1 data cache or last level cache misses. |
| [ebpf-profile-lockwait](https://github.com/ebpf-profiler-probes/ebpf-profile-lockwait) | Profiles which call sites wait on locks and for how long. |
