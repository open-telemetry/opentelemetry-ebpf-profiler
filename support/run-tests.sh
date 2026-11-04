#!/usr/bin/env bash
# Test the current package under a different kernel.
# Requires qemu-system-$QEMU_ARCH and bluebox to be installed.
# Missing kernel images are downloaded from Cilium using Docker.

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

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi
readonly sudo

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$qemu_arch" == x86_64 ]]
then
  kernel_arch=amd64
elif [[ "$qemu_arch" == aarch64 ]]
then
  kernel_arch=arm64
else
  fail "Unsupported QEMU architecture: $qemu_arch"
fi
readonly kern_dir="${KERN_DIR:-$repo_root/ci-kernels/$kernel_arch}"

download_kernel() (
  kernel_dir="$kern_dir/$kernel_version"
  if [[ -s "$kernel_dir/vmlinuz" ]]
  then
    return
  fi
  [[ "$kernel_version" =~ ^[0-9][a-zA-Z0-9._-]*$ ]] || fail "Invalid kernel version: $kernel_version"
  command -v docker >/dev/null || fail "Docker is required to download kernel $kernel_version (see support/README.md)"
  mkdir -p "$kernel_dir"
  download_dir="$(mktemp -d "$kernel_dir/.download.XXXXXX")"
  kernel_container=""
  trap '
    if [[ -n "$kernel_container" ]]
    then
      docker rm "$kernel_container" >/dev/null || true
    fi
    rm -rf "$download_dir"
  ' EXIT

  echo "Downloading Linux $kernel_version for $kernel_arch"
  kernel_container="$(docker create --pull=always --platform "linux/$kernel_arch" "ghcr.io/cilium/ci-kernels:$kernel_version" /bin/true)"
  docker cp "$kernel_container:/boot/vmlinuz" "$download_dir/vmlinuz"
  [[ -s "$download_dir/vmlinuz" ]] || fail "Downloaded kernel image is empty"
  mv "$download_dir/vmlinuz" "$kernel_dir/vmlinuz"
)

download_kernel

echo Generating initramfs
expected=0
bb_args=()
while IFS='' read -r -d '' line ; do
    bb_args+=(-e "${line}:-test.v")
    ((expected=expected+1))
done < <(find "$repo_root/support" -name '*.test' -print0)
((expected > 0)) || fail "No test binaries in $repo_root/support"
readonly output="$(mktemp -d --suffix=-output)"
bb_args+=(-o "${output}/initramfs.cpio")

additionalQemuArgs=""

supportKVM=$(grep -E 'vmx|svm' /proc/cpuinfo || true)
if [ -n "$supportKVM" ] && [ "$qemu_arch" = "$(uname -m)" ]; then
  additionalQemuArgs="-enable-kvm"
fi

case "$qemu_arch" in
    x86_64)
        additionalQemuArgs+=" -cpu Haswell -append console=ttyS0"
        bb_args+=(-a amd64)
        ;;
    aarch64)
        # Newer Linux kernels may fail to load with QEMU for arm64.
        # This issue has been addressed in QEMU 9.2+ by
        # https://github.com/qemu/qemu/commit/1505b651fdbd9af59a4a90876a62ae7ea2d4cd39.
        #
        # To test newer Linux kernels with older QEMU versions, a dedicated,
        # unaffected CPU should be set for the QEMU configuration.
        additionalQemuArgs+=" -machine virt -cpu cortex-a72"
        bb_args+=(-a arm64)
        ;;
esac

bluebox "${bb_args[@]}" || (echo "failed to generate initramfs"; exit 1)

echo Testing on "${kernel_version}"
$sudo qemu-system-${qemu_arch} ${additionalQemuArgs} \
	-nographic \
	-monitor none \
	-chardev stdio,id=char0,logfile="${output}/test.log",signal=off \
	-serial chardev:char0 \
	-no-user-config \
	-m 4G \
	-kernel "${kern_dir}/${kernel_version}/vmlinuz" \
	-initrd "${output}/initramfs.cpio"

# Qemu will produce an escape sequence that disables line-wrapping in the terminal,
# end result being truncated output. This restores line-wrapping after the fact.
if [[ -t 1 && -n "${TERM:-}" ]]; then
  tput smam || true
fi

passes=$(grep -c "stdout: PASS" "${output}/test.log" || true)

if [[ "$passes" -ne "$expected" ]]; then
  echo "Test ${color_red}failed${color_default} on ${kernel_version}"
  EXIT_CODE=1
else
  echo "Test ${color_green}successful${color_default} on ${kernel_version}"
  EXIT_CODE=0
fi

$sudo rm -rf "${output}"

exit $EXIT_CODE
