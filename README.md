# Introduction

This repository implements a whole-system, cross-language profiler for Linux via
eBPF.

## Core features and strengths

- Implements the [Alpha OTel Profiles signal](https://github.com/open-telemetry/opentelemetry-proto/pull/775)
- Very low CPU and memory overhead (1% CPU and 250MB memory are our upper limits
  in testing and the agent typically manages to stay way below that)
- Support for native C/C++ executables without the need for DWARF debug
  information (by leveraging `.eh_frame` data as described in
  [US11604718B1](https://patents.google.com/patent/US11604718B1/en?inventor=thomas+dullien&oq=thomas+dullien))
- Support profiling of system libraries **without frame pointers** and **without
  debug symbols on the host**.
- Support for mixed stacktraces between runtimes - stacktraces go from Kernel
  space through unmodified system libraries all the way into high-level
  languages.
- Support for native code (C/C++, Rust, Zig, Go, etc. without debug symbols on
  host)
- Support for a broad set of HLLs, like Hotspot JVM, Python, Ruby, PHP, Node.JS,
  V8, Perl, Erlang and .NET.
- 100% non-intrusive: there's no need to load agents or libraries into the
  processes that are being profiled.
- No need for any reconfiguration, instrumentation or restarts of HLL
  interpreters and VMs: the agent supports unwinding each of the supported
  languages in the default configuration.
- ARM64 support for all unwinders except .NET.
- Support for native `inline frames`, which provide insights into compiler
  optimizations and offer a higher precision of function call chains.

## Building

We have integrated the profiler into the [OTel Collector](https://opentelemetry.io/docs/collector/) as a receiver,
and this is the [supported configuration](https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-ebpf-profiler) going forward.

To aid with development, testing and debugging, we also offer a standalone profiling agent binary named `ebpf-profiler`,
and a local build of an OTel Collector profiling receiver binary (`otelcol-ebpf-profiler`). These binaries are not
supported in any way, can be dropped in the future and should not be deployed in production.

## Platform Requirements
The agent can be built with the provided make targets. Docker is required for containerized builds, and both amd64 and arm64 architectures are supported.

 For **Linux**, the following steps apply:
  1. Build the agent for your current machine's architecture:
     ```sh
     make agent
     ```
     Or `make debug-agent` for debug build.
  2. To cross-compile for a different architecture (e.g. arm64):
     ```sh
     make agent TARGET_ARCH=arm64
     ```
The resulting binary will be named `ebpf-profiler` in the current directory.

## Other OSes
Since the profiler is Linux-only, macOS and Windows users need to set up a Linux VM to build and run the agent. Ensure the appropriate architecture is specified if using cross-compilation. Use the same make targets as above after the Linux environment is configured in the VM.

## Supported Linux kernel version

The minimum required Linux kernel version has increased with certain commits. Specifically:

- Commit [8047150e](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/commit/8047150e3f325f852874591356c69d0487b67d7c) was the last to support kernel version 5.4. Subsequent changes may require a minimal Linux kernel version of 5.10 or greater.
- Commit [7ddc23ea](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/commit/7ddc23ea135a2e00fffc17850ab90534e9b63108) was the last to support kernel version 4.19. Subsequent changes may require a minimal Linux kernel version of at least 5.4.

### Updating the supported Linux kernel version

The project maintains its minimum supported kernel version in line with the lowest kernel version currently provided by actively maintained major Linux distributions, which include Debian stable, Red Hat Enterprise Linux, Ubuntu LTS, Amazon Linux and SUSE Linux. The minimum requirement may be increased when all such distributions no longer ship a specific kernel version. This approach enables the codebase to utilize newer eBPF features and avoids the need to maintain compatibility shims for obsolete kernels.

It should be noted that certain distributions incorporate eBPF features from newer kernels into their supported versions. When this occurs, the distribution's stated kernel version does not accurately reflect its true eBPF capabilities and will not prevent us from increasing the minimum supported version. On such kernels, the `no-kernel-version-check` configuration option can be used to bypass the checks and allow the profiler to execute.

## Alternative Build (Without Docker)
You can build the agent without Docker by directly installing the dependencies listed in the Dockerfile. Once dependencies are set up, simply run:
```sh
make
```
or
```sh
make debug
```
This will build the profiler natively on your machine.

## Building `otelcol-ebpf-profiler` locally (Without Docker)
You can build the local `otelcol-ebpf-profiler` binary by running:
```sh
make otelcol-ebpf-profiler
```
or to cross-compile for a different architecture (e.g. arm64):
```sh
make otelcol-ebpf-profiler TARGET_ARCH=arm64
```

See [local.example.yml](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/cmd/otelcol-ebpf-profiler/local.example.yaml) for an example configuration.

## Running

You can start the agent with the following command:

```sh
sudo ./ebpf-profiler -collection-agent=127.0.0.1:11000 -disable-tls
```

To start the OTel Collector profiling receiver, run:
```sh
sudo ./otelcol-ebpf-profiler --feature-gates=+service.profilesSupport --config cmd/otelcol-ebpf-profiler/local.example.yaml
```

The agent comes with a functional but work-in-progress / evolving implementation
of the recently released Alpha OTel Profiles [signal](https://github.com/open-telemetry/opentelemetry-proto/pull/775).

The agent loads the eBPF program and its maps, starts unwinding and reports
captured traces to the backend.

## Open Source Backends
As the OTel Profiles signal is still in development, mature production-ready
backends have yet to emerge. The following open source projects can be used as backends:

- [devfiler](https://github.com/elastic/devfiler) — to speed up development and
  experimentation, Elastic has open-sourced a desktop application that
  reimplements the backend (collection, data storage, symbolization and UI)
  portion of the eBPF profiler. Note that devfiler is not a real production
  backend and should not be used as such. It is solely aimed at testing,
  experimentation and development.
- [Pyroscope](https://github.com/grafana/pyroscope) — an open source continuous
  profiling database that natively supports ingesting OTel profiling data.

## Development

To understand how this project works and learn more about profiling, check out [Profiling internals](doc/internals.md)

# Legal

## Licensing Information

This project is licensed under the Apache License 2.0 (Apache-2.0).
[Apache License 2.0](LICENSE)

The eBPF source code is licensed under the GPL 2.0 license.
[GPL 2.0](support/ebpf/LICENSE)

## Licenses of dependencies

To display a summary of the dependencies' licenses:
```sh
make legal
```
