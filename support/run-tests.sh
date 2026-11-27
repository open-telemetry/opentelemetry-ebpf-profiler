#!/usr/bin/env bash
# Run prebuilt integration tests on one or more kernels.
# Requires qemu-system-$QEMU_ARCH; needs bluebox or Go when --initramfs is not
# used. Missing kernel images are downloaded from Cilium using Docker.
# --initramfs <path> reuses a prebuilt initramfs (with sibling .manifest) as
# the first argument instead of generating one.

set -eu
set -o pipefail

fail() {
  echo "$*" >&2
  exit 1
}

qemu_arch="${QEMU_ARCH:-$(uname -m)}"
color_green=$'\033[32m'
color_red=$'\033[31m'
color_default=$'\033[39m'

# Use sudo if /dev/kvm isn't accessible by the current user. Root needs none,
# and container images such as the repository's may not ship it.
sudo=""
if [[ $EUID -ne 0 && ( ! -r /dev/kvm || ! -w /dev/kvm ) ]]; then
  sudo="sudo"
fi
readonly sudo

prebuilt_initramfs=""
if [[ "${1:-}" == "--initramfs" ]]; then
  (( $# >= 2 )) || fail "--initramfs requires a path argument"
  prebuilt_initramfs="$2"
  shift 2
fi

(( $# > 0 )) || fail "Expecting one or more kernel versions as arguments"
for kernel_version in "$@"
do
  [[ "$kernel_version" =~ ^[0-9][a-zA-Z0-9._-]*$ ]] || fail "Invalid kernel version: $kernel_version"
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$qemu_arch" in
  x86_64) kernel_arch=amd64 ;;
  aarch64) kernel_arch=arm64 ;;
  *) fail "Unsupported QEMU architecture: $qemu_arch" ;;
esac
readonly kern_dir="${KERN_DIR:-$repo_root/ci-kernels/$kernel_arch}"

command -v "qemu-system-$qemu_arch" >/dev/null || fail "Missing dependency: qemu-system-$qemu_arch (see support/README.md)"
if [[ -z "${prebuilt_initramfs}" ]]; then
  command -v bluebox >/dev/null || command -v go >/dev/null || fail "Missing dependency: bluebox or go (see support/README.md)"
fi

download_kernel() (
  kernel_dir="$kern_dir/$kernel_version"
  if [[ -s "$kernel_dir/vmlinuz" ]]
  then
    return
  fi
  if [[ -n "${KERN_DIR:-}" ]]
  then
    echo "Kernel image $kernel_dir/vmlinuz is missing or empty; falling back to ghcr.io/cilium/ci-kernels:$kernel_version" >&2
  fi
  command -v docker >/dev/null || fail "Docker is required to download kernel $kernel_version (see support/README.md)"
  # The caller checks this function's status, so failures must return explicitly.
  mkdir -p "$kernel_dir" || return
  download_dir="$(mktemp -d "$kernel_dir/.download.XXXXXX")" || return
  trap 'rm -rf "$download_dir"' EXIT

  echo "Downloading Linux $kernel_version for $kernel_arch"
  echo "FROM ghcr.io/cilium/ci-kernels:$kernel_version" |
    docker buildx build --platform "linux/$kernel_arch" --quiet --pull --output "$download_dir" - || return
  mv "$download_dir/boot/vmlinuz" "$kernel_dir/vmlinuz"
)

output="$(mktemp -d --suffix=-output)"
readonly output
trap '$sudo rm -rf "$output"' EXIT

additionalQemuArgs=""
kernelCmdline="quiet"

case "$qemu_arch" in
    x86_64)
        kernelCmdline="console=ttyS0 ${kernelCmdline}"
        ;;
    aarch64)
        additionalQemuArgs+=" -machine virt"
        ;;
esac

if [[ -n "${prebuilt_initramfs}" ]]; then
    [ -e "$prebuilt_initramfs" ] && [ -e "${prebuilt_initramfs%.cpio}.manifest" ] || fail "Prebuilt initramfs or manifest missing: $prebuilt_initramfs"
    initramfs_path="$prebuilt_initramfs"
else
    echo Generating initramfs
    initramfs_path="${output}/initramfs-${kernel_arch}.cpio"
    (cd "$repo_root/support" && ./gen-initramfs.sh "${initramfs_path}" "${kernel_arch}") || fail "failed to generate initramfs"
fi
expected="$(grep -c . "${initramfs_path%.cpio}.manifest" || true)"
((expected > 0)) || fail "No test binaries in ${initramfs_path%.cpio}.manifest"

# Enable KVM when the guest architecture matches the host and /dev/kvm is
# available. Otherwise pick a CPU model for full TCG emulation.
if [ -c /dev/kvm ] && [ "$qemu_arch" = "$(uname -m)" ]; then
  additionalQemuArgs+=" -enable-kvm -cpu host"
elif [ "$qemu_arch" = "x86_64" ]; then
  additionalQemuArgs+=" -cpu Haswell"
elif [ "$qemu_arch" = "aarch64" ]; then
  # Newer Linux kernels may fail to load with QEMU for arm64 on versions
  # older than 9.2. This issue has been addressed in QEMU 9.2+ by
  # https://github.com/qemu/qemu/commit/1505b651fdbd9af59a4a90876a62ae7ea2d4cd39.
  #
  # Detect support by probing for the virt-9.2 machine type, which QEMU
  # first shipped in that same release (plain "virt" aliases the newest
  # machine type). There prefer -cpu neoverse-n1: it has LSE atomics but
  # lacks the PAC/SME/SVE extensions that cost TCG emulation time. Older
  # QEMU versions need the Cortex-A72 model as a fallback.
  if qemu-system-aarch64 -machine help | grep 'virt-9\.2' >/dev/null; then
    additionalQemuArgs+=" -cpu neoverse-n1"
  else
    additionalQemuArgs+=" -cpu cortex-a72"
  fi
fi

smp="$(nproc 2>/dev/null || echo 4)"
[ "$smp" -gt 4 ] && smp=4

failed_kernels=()
for kernel_version in "$@"
do
  if ! download_kernel
  then
    failed_kernels+=("$kernel_version")
    continue
  fi

  echo Testing on "${kernel_version}"
  test_log="$output/$kernel_version.log"
  qemu_status=0
  $sudo qemu-system-${qemu_arch} ${additionalQemuArgs} \
	-nographic \
	-monitor none \
	-nic none \
	-smp "$smp" \
	-chardev stdio,id=char0,logfile="${test_log}",signal=off \
	-serial chardev:char0 \
	-no-user-config \
	-m 4G \
	-kernel "${kern_dir}/${kernel_version}/vmlinuz" \
	-initrd "${initramfs_path}" \
	-append "${kernelCmdline}" || qemu_status=$?

  # Qemu disables terminal line-wrapping; restore it after each run.
  if [[ -t 1 && -n "${TERM:-}" ]]; then
    tput smam || true
  fi

  passes=$(grep -c "stdout: PASS" "$test_log" || true)

  if [[ "$qemu_status" -ne 0 || "$passes" -ne "$expected" ]]; then
    echo "Test ${color_red}failed${color_default} on ${kernel_version}"
    failed_kernels+=("$kernel_version")
  else
    echo "Test ${color_green}successful${color_default} on ${kernel_version}"
  fi
done

if [[ "${#failed_kernels[@]}" -gt 0 ]]
then
  fail "Integration tests failed on $kernel_arch kernels: ${failed_kernels[*]}"
fi
echo "Integration tests passed on $kernel_arch kernels: $*"
