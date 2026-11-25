# Threat model

See the [Security Policy](SECURITY.md) and the
[OpenTelemetry security policy](https://github.com/open-telemetry/.github/blob/main/SECURITY.md).
The sections below add context for automated review.

## What this project does and where untrusted input enters

A whole-system Linux profiler. It loads eBPF programs, samples every process on the host, unwinds native stacks and the
stacks of language runtimes (one package per runtime under `interpreter/`), symbolizes frames and reports them as OTLP
profiles through the OpenTelemetry Collector. It is a Go library used as a Collector
receiver, `cmd/otelcol-ebpf-profiler` is a local test binary and not an official distribution. It runs as root or with
`CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_ADMIN`, so a flaw in it is a flaw in a privileged host process.

The profiled processes are the untrusted party. Everything below is controlled by whoever runs code on the host,
including a container with no privileges.

- Process memory and registers read from other processes by the eBPF programs (`support/ebpf`) and by user space
  (`remotememory`). Interpreter structures, stacks, TLS and thread-local data are all attacker shaped.
- ELF files mapped by any process, read through `/proc/<pid>/root` and `/proc/<pid>/map_files`. This covers `libpf/pfelf`,
  `.eh_frame` and `.gopclntab` parsing in `nativeunwind`, `usdt` notes, `asm/amd` and `asm/arm` instruction decoding,
  and build ID and file ID hashing. Files inside a container can be replaced or made to look like anything.
- Runtime introspection data of each supported interpreter and VM, such as exported offset tables, symbol tables and
  internal structures that the unwinders in `interpreter/` read from the target.
- The OTel process context and thread context a process publishes (`process/processcontext`,
  `interpreter/threadcontext`), including protobuf payloads, labels and attributes.
- Process names, command lines, cgroup paths, environment-derived attributes and mount namespace layout.

Trusted input.

- The agent configuration, command line flags and Collector configuration. Whoever sets them already controls the agent.
- The kernel, its BTF and `/proc/kallsyms`, the eBPF verifier, and the hardware. An access the verifier rejects is not a
  finding, as the program would not load. See the eBPF rules in the severity section.
- The Collector pipeline and the backend the exporter sends to.
- Test fixtures and coredumps under `testdata/`, including `tools/coredump`.

The project's position, from [SECURITY.md](SECURITY.md), is that a crafted executable or interpreter library in the profiled process
causing denial of service or excessive resource use is a bug and not a vulnerability. See the severity section for how
that is handled.

## Security guarantees

Intended operations, which are not findings by themselves.

- The agent reads memory, files and metadata of the processes it profiles, as root, and exports the resulting profiles
  to the backend the operator configured. That is its job. The operator chooses which interpreters and probes read what.
- Reporting what a process published about itself, such as frames, symbol names, labels, attributes and process context.

What the agent promises.

- Data read from one process is not attributed to another process or container, and is not disclosed to one.
- A process cannot make the agent execute arbitrary code.
- A process cannot corrupt the attribution of another process, by colliding or reusing identifiers such as file IDs,
  trace hashes, pids or cache entries.

What it does not promise. Stacks, symbols, labels, attributes and context from a process are claims by that process and
are not authenticated. A process can fabricate telemetry about itself, including names that mimic another service. That
is not a finding unless it changes what is reported for a different process, or what the agent reads.

A disclosure finding states what data is exposed and to whom. The recipient must be one that is not already entitled to
the data. The configured backend is trusted and receives profiles of every process, so data of container A showing up
in a profile attributed to container B is misattribution and not disclosure by itself. It becomes disclosure when it
reaches another container or process, or a backend identity or tenant that is not entitled to A's data, and the finding
shows that new access. Data a process published about itself and received back in its own profile is not a disclosure.

## Components that matter most / least

Most.

- `support/ebpf` C code. Trusting a value read from user memory as a length or index, integer width and signedness
  errors, and accesses to map values or the stack that the verifier can accept but that are wrong at run time. Faults on
  reads of user memory are not findings by themselves, as the probe read helpers return an error. Mishandling that error
  is, for example using a stale or uninitialized buffer, or leaving a map entry of another process in place.
- `probes/heap` and `probes/uprobe`. The operator enables them, but they act on mappings of the profiled process.
  `probes/heap` discovers USDT notes in every executable mapping and parses their argument descriptions in
  `probes/heap/usdt.go`, and the note contents, offsets and registers come from a target controlled ELF. `probes/uprobe`
  attaches to a mapping of the target through an opened file descriptor.
- `libpf/pfelf`, `nativeunwind`, `usdt` and `asm`. Parsers of attacker supplied files and instructions. Look for
  out of range slicing, integer overflow in offset arithmetic, unbounded allocation from a header field, and reads that
  escape the intended file.
- `libc` and `tls`. They parse and decode the C library of the target to find the TSD and DTV layout, and resolve
  thread-local variables in its memory. The offsets they derive drive the thread pointer reads in `support/ebpf`.
- `process` and `remotememory`. How files and memory of another process are reached. A path or symlink that leaves
  the target root, a file descriptor leak, a pid reuse race, and reading or caching data of one process under the
  identity of another.
- `interpreter/*`. Each unwinder reads and trusts structures of the target. A pointer chain, array length or string
  length taken from process memory must be bounded before it is used for allocation or iteration.
- `processmanager`, `tracer` and `reporter`. Where data of one process or container could be attributed to another, such
  as file ID, trace hash and frame cache collisions, label or attribute leakage across pids, and stale entries after pid
  reuse. `processmanager/ebpf` writes the per-pid eBPF maps. `tracer` drains the pid events and decodes the trace
  records and labels the eBPF programs emit.
- `process/processcontext` and `interpreter/threadcontext`. Protobuf decoding of data a process controls, and the eBPF
  slots and maps they write.

Least, still in scope.

- `collector` and `reporter` option plumbing, `metrics`, `times`, `periodiccaller` and other helpers.
- `probes/kprobe` and `probes/offcpu`, which act on operator configuration and kernel symbols only.

Out of scope.

- `tools/` (coredump, luajitoffsets, stackdeltas, gooffsets, zstpak, errors-codegen, file_id.sh), which are developer
  tools run on trusted input.
- `testsupport`, `*_test.go`, `testdata/`, `ci-kernels/`, `design-docs/`, `doc/`, `LICENSES/` and `.github/`.
- `cmd/otelcol-ebpf-profiler/*.go` and its `go.mod`, which are generated by `make generate-collector`.
- Generated files such as `metrics/ids.go`. A flaw in one is in scope but must be fixed in the generator or its
  source (`metrics/metrics.json`).

## How to exercise it

- In the scanner image, the agent is built at `/usr/local/bin/otelcol-ebpf-profiler`. Loading the eBPF programs needs a
  privileged host with a kernel 5.10 or newer and is probably not possible here, so do not rely on running the full agent.
  When the environment supports it, run with the required profiles feature gate and Collector configuration:

  ```sh
  /usr/local/bin/otelcol-ebpf-profiler \
    --feature-gates=+service.profilesSupport \
    --config=/src/cmd/otelcol-ebpf-profiler/local.example.yaml
  ```

  Run as root (use `sudo` on a suitable host if needed); root inside an unprivileged container is not sufficient.
  The example exports to `http://127.0.0.1:11000` by default, overridable through `OTEL_EXPORTER_OTLP_ENDPOINT`.
  Without a reachable OTLP receiver, expect export failures. Startup failures caused by missing privileges or kernel
  support are environment limitations, not findings. Use unit tests and the coredump harness below when full-agent
  execution is unavailable.
- The eBPF code is the blob `/src/support/ebpf/tracer.ebpf.<arch>`, built from `support/ebpf/*.c` with clang-17. After a
  change to the C code run `make format-ebpf` in `/src` to format it, then `make amd64 arm64 -C support/ebpf` to rebuild
  both blobs. The repository's CI rebuilds the blobs and requires them to match what is committed, so a patch to the C
  code must include the rebuilt blobs.
- Most of the code is reachable from Go unit tests, run from `/src` with `go test ./...`. The `tools/coredump`
  module is separate, run `cd /src/tools/coredump && go test ./...`. It compiles the whole eBPF unwinder into a user space
  program with cgo and runs it against recorded coredumps of real interpreters. This is the way to exercise `support/ebpf`
  without a kernel. The coredump modules were fetched during the image build into `tools/coredump/modulecache`.
- The coredump harness is not the kernel. It builds the C code with `TESTING_COREDUMP` as native code, with the
  helpers, maps and memory reads of `support/ebpf/bpfdefs.h` and `tools/coredump` emulated in Go and C. No verifier runs
  and the program sees a flat address space. A crash or out of bounds access there shows a bug in the C logic, and does not
  show that the same access happens in the kernel.
- To validate eBPF behavior on a real kernel, use `make integration-tests KERNEL_VERSIONS=5.10.217` from the repository
  root when the required dependencies are available. This builds test binaries and an initramfs, then runs them in QEMU
  with the kernel verifier active. `TARGET_ARCH` defaults to the host architecture; omitting `KERNEL_VERSIONS` runs the
  full CI kernel matrix for that architecture. QEMU can use software emulation without KVM, but it is much slower.
  The scanner image does not provision QEMU or kernel images for this target. Offline use also requires prefetching
  the additional Go toolchains and build dependencies; missing kernels are normally downloaded using Docker.
  See [support/README.md](support/README.md) for setup and cached-kernel locations. Run `make host-integration-tests`
  separately on a suitably privileged host for process-context and TLS tests that are not in the QEMU suite.
- Fuzz targets exist in `usdt/notes_test.go`, `usdt/arguments_test.go`, `asm/amd/interpreter_test.go` and
  `interpreter/python/decode_test.go`. Others can be written against a
  parser such as `pfelf.NewFile` or `elfunwindinfo.Extract` and fed with `go test -fuzz`.
- Fixtures for ELF and unwind info tests are in `libpf/pfelf/testdata` and `nativeunwind/elfunwindinfo/testdata`.
- There is no network and `GOPROXY=off`. Modules and the Go build cache were fetched during the image build.
- Fixture setup (`make test-deps`) must succeed for the image to build. The root module and `tools/coredump` test
  suites are then attempted independently, with output in `/opt/oss-scanner-test.log`. Test failures do not abort the
  image build. Check the log for failures and skipped tests before treating a failure as new. Tests tagged
  `integration` or `host_integration` are not run.
- Only the native architecture is built. Code under `*_amd64.go` and `*_arm64.go` and the `.arm64` fixtures are still
  in scope, read them even when they cannot be run.

## How you rate severity

Use the [OpenTelemetry severity guidelines](https://github.com/open-telemetry/sig-security/blob/main/security-response.md#severity)
with the model above.

The tiers below are this project's triage defaults for the scanner. They are subordinate to the OpenTelemetry guidance
above, which uses CVSS v4.0. Start from the first tier that matches. If the CVSS v4.0 score for the finding disagrees,
give the vector and the reasoning, and the score decides. The exclusions in [SECURITY.md](SECURITY.md) take precedence
over the score. A finding they cover stays a bug and not a vulnerability whatever it scores, and the score only moves
findings they do not cover. Each finding gets one rating. The attacker is a hostile
profiled process, with no privileges on the host beyond running code in a container. For cross-process disclosure no
attacker is needed, an accidental one is rated the same way. Misattribution is rated by whether a profiled process can
cause it, see the Medium and Low tiers.

- Critical. Code execution in the agent, or a write to the host or to another process that the attacker controls in
  content and destination, beyond what the agent writes by design such as logs, metrics and reports. A constrained write
  with no demonstrated effect is not Critical, rate it by its effect.
- High. Any of the following. Memory corruption in the agent (out of bounds write, use after free). An out of bounds read
  in the agent whose result reaches the report or another process. A read of an arbitrary host file
  or of sensitive agent memory, such as keys, credentials or tokens, whose content reaches the report. Data of one
  container or process that discloses a secret, such as credentials, keys or tokens, to a recipient not entitled to it.
- Medium. Any of the following. Data of one container or process disclosed to a recipient not entitled to it that is
  metadata only, such as command lines, paths, environment-derived attributes or labels. A profiled process that changes
  what is reported for a different process, by colliding or reusing identifiers such as file IDs, trace hashes, pids or
  cache entries, or by leaving state that samples of the other process pick up. That breaks the attribution guarantee
  above and is rated Medium whether or not a recipient gains new access.
- Low, labelled "bug, not a vulnerability". Denial of service by a crafted executable in the profiled process, and
  denial of service or excessive resource usage by a crafted library mimicking a supported high-level language and
  providing malformed introspection data. This includes a crash, hang, leak or an unbounded allocation sized by a value
  from process memory. These follow [SECURITY.md](SECURITY.md) and the maintainers handle them as normal bugs. If the same flaw also gives memory
  corruption or data disclosure, rate that consequence instead.
- Low, labelled "bug, not a vulnerability". A stack or attribution that is wrong without a profiled process causing it.
  Give the input and the expected and actual frames. This includes data of one process reported under another when no
  recipient gains access it did not already have, as the backend receives every profile. That is project policy and not
  an exclusion from [SECURITY.md](SECURITY.md). If a profiled process can cause it, rate it as misattribution above. If a
  recipient gains new access, rate it as disclosure above.

eBPF code is rated by what happens in the kernel. A finding in `support/ebpf` needs all of the following.

- The access is one the verifier accepts when the program is loaded, on at least one supported kernel. Name its version
  and the relevant configuration.
- It is not a plain fault of a probe read helper, which returns an error. Mishandling that error is a finding.
- It happens with input a profiled process can produce, and the effect is on the kernel, the agent or the report.
- It is shown by reasoning from the C code and the verifier's rules, or on a real kernel.

A crash, assertion or out of bounds access in the coredump harness alone is a lead and not a finding, as the harness
differs from the kernel in memory layout and has no verifier. Report it only once the rules above show the same input
reaching the kernel, and rate it by the effect there. A defect in the harness emulation itself is in `tools/` and out of
scope.
A wrong value from the eBPF code that only changes the stack in the report is a correctness bug, unless the stack or the
map entry holds data of another process. That is misattribution or disclosure as above.

A finding needs a concrete path from the input that reaches the agent to the unintended behavior, ideally with a
reproducer. The input can be a profiled process, a file, or anything else the agent interacts with. If a step cannot be
shown, do not report it.

## Anything to leave alone / out of scope

- Anything that needs control of the configuration, the Collector pipeline, the kernel, or root on the host.
- A process that is not profiled, or a profiled process that can only hurt itself.
- Denial of service by a crafted profiled process is a Low bug, see above.
- Weaknesses in the Go standard library or a dependency that cannot be reached from this code. If one can, show the call path.
- Eavesdropping on or tampering with the connection to the backend when the operator configured it without TLS.
