#!/usr/bin/env bash
# Run prebuilt integration tests on cached CI kernel images.

set -euo pipefail

fail() {
  echo "$*" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || fail "Run these targets in a Linux build environment"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

target_arch="${1:-}"
if [[ "$target_arch" == amd64 ]]
then
  qemu_arch=x86_64
elif [[ "$target_arch" == arm64 ]]
then
  qemu_arch=aarch64
else
  fail "Unsupported architecture: $target_arch (expected amd64 or arm64)"
fi

if [[ "${2:-}" == --all ]]
then
  # Read the inline CI matrix entries so the local kernel list stays in sync.
  mapfile -t kernel_versions < <(sed -nE \
    "s/^[[:space:]]*- \{ target_arch: ${target_arch}, kernel: ([^ ,}]+) \}.*/\1/p" \
    "$repo_root/.github/workflows/unit-test-on-pull-request.yml")
  [[ "${#kernel_versions[@]}" -gt 0 ]] || fail "No CI kernels found for $target_arch"
else
  [[ -n "${2:-}" ]] || fail "Set KERNEL_VERSION, for example: make integration-tests TARGET_ARCH=amd64 KERNEL_VERSION=5.10.217"
  kernel_versions=("$2")
fi

for kernel_version in "${kernel_versions[@]}"
do
  [[ "$kernel_version" =~ ^[0-9][a-zA-Z0-9._-]*$ ]] || fail "Invalid kernel version: $kernel_version"
done

for dependency in bluebox "qemu-system-$qemu_arch"
do
  command -v "$dependency" >/dev/null || fail "Missing dependency: $dependency (see support/README.md)"
done

failed_kernels=()
for kernel_version in "${kernel_versions[@]}"
do
  if ! QEMU_ARCH="$qemu_arch" "$repo_root/support/run-tests.sh" "$kernel_version"
  then
    failed_kernels+=("$kernel_version")
  fi
done

if [[ "${#failed_kernels[@]}" -gt 0 ]]
then
  fail "Integration tests failed on $target_arch kernels: ${failed_kernels[*]}"
fi
echo "Integration tests passed on $target_arch kernels: ${kernel_versions[*]}"
