This directory is intended for non-Go support functionality. For example, the
eBPF code and supporting Python scripts for bytecode offsets to line number
translation.

## Testing on CI kernels

From the repository root, run the QEMU integration tests on a specific kernel:

```sh
make integration-tests TARGET_ARCH=amd64 KERNEL_VERSION=5.10.217
```

To run on every kernel in the CI matrix for an architecture:

```sh
make integration-tests-all TARGET_ARCH=amd64
make integration-tests-all TARGET_ARCH=arm64
```

`TARGET_ARCH` defaults to the host architecture. The all-kernels target reads
kernel versions from `.github/workflows/unit-test-on-pull-request.yml`, builds
the test binaries once, runs every kernel, and fails if any kernel fails.

`run-tests.sh` always reads test binaries from the repository's `support/`
directory, regardless of the working directory. It defaults to the Linux host's
architecture; set `QEMU_ARCH=x86_64` or `QEMU_ARCH=aarch64` to override it.

Missing images are downloaded from `ghcr.io/cilium/ci-kernels` into
`ci-kernels/<arch>/<version>/vmlinuz` at the repository root. Cached images are
never refreshed. Tags such as `6.16` move to newer patch releases, so delete the
cached image to match CI.

Run `make host-integration-tests` separately for the process context and TLS
tests, which need shared libraries unavailable in the QEMU initramfs.

## Requirements
Linux with the project build dependencies, QEMU for the target architecture,
`bluebox`, and Docker for downloading kernels. On Debian or Ubuntu:

```sh
sudo apt-get install qemu-system-x86 qemu-system-arm ipxe-qemu
go install github.com/florianl/bluebox@v0.0.1
export PATH="$(go env GOPATH)/bin:$PATH"
```

Cross compilation needs the target architecture's C compiler. `run-tests.sh`
uses `sudo` when `/dev/kvm` is inaccessible. Without KVM, QEMU is much slower.

## Test a Custom Kernel Image
Kernel images can be built with [cilium/ci-kernels](https://github.com/cilium/ci-kernels).
Place the image at `$KERN_DIR/<version>/vmlinuz` and pass its version to
`run-tests.sh`. `KERN_DIR` replaces `ci-kernels/<arch>`, so use one directory
per architecture.
```
$ KERN_DIR=my-other-kernels/ ./support/run-tests.sh 5.4.276
```

 ## Manually Debugging a Custom Kernel Image
1. Compile eBPF and Go code
```
$ make ebpf
$ cd support
$ go test -c -tags integration ./...
```
2. Get [virtme](https://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git/) to run the environment
```
$ tmp_virtme="$(mktemp -d --suffix=-virtme)"
$ git clone -q https://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git "${tmp_virtme}"
```
3. Start the virtual environment for debugging with gdb:
```
$ ${tmp_virtme}/virtme-run --kimg  ci-kernels/linux-5.4.276.bz \
    --memory 4096M \
    --pwd \
    --script-sh "mount -t bpf bpf /sys/fs/bpf ; ./support.test -test.v" \
    --qemu-opts -append nokaslr -s
```
4. Start gdb in a second shell:
```
$ cd support
$ gdb
# Attach gdb to the running qemu process in the same directory:
(gdb) target remote localhost:1234
# Load source code:
(gdb) directory ./ci-kernels/_build/linux-5.4.276
# Load symbols for debugging:
(gdb) sym ./ci-kernels/_build/linux-5.4.276/vmlinux
# Set breakpoint at entry of eBPF verifier:
(gdb) break do_check
Breakpoint 1 at 0xffffffff81184460: file kernel/bpf/verifier.c, line 4105.
```
