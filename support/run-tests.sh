#!/usr/bin/env bash
# Run prebuilt integration tests on one or more kernels.
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

(( $# > 0 )) || fail "Expecting one or more kernel versions as arguments"
for kernel_version in "$@"
do
  [[ "$kernel_version" =~ ^[0-9][a-zA-Z0-9._-]*$ ]] || fail "Invalid kernel version: $kernel_version"
done

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

for dependency in bluebox "qemu-system-$qemu_arch"
do
  command -v "$dependency" >/dev/null || fail "Missing dependency: $dependency (see support/README.md)"
done

download_kernel() (
  kernel_dir="$kern_dir/$kernel_version"
  if [[ -s "$kernel_dir/vmlinuz" ]]
  then
    return
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

echo Generating initramfs
expected=0
bb_args=()
while IFS='' read -r -d '' line ; do
    bb_args+=(-e "${line}:-test.v")
    ((expected=expected+1))
done < <(find "$repo_root/support" -name '*.test' -print0)
((expected > 0)) || fail "No test binaries in $repo_root/support"
output="$(mktemp -d --suffix=-output)"
readonly output
trap '$sudo rm -rf "$output"' EXIT
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

bluebox "${bb_args[@]}" || fail "failed to generate initramfs"

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
	-chardev stdio,id=char0,logfile="${test_log}",signal=off \
	-serial chardev:char0 \
	-no-user-config \
	-m 4G \
	-kernel "${kern_dir}/${kernel_version}/vmlinuz" \
	-initrd "${output}/initramfs.cpio" || qemu_status=$?

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
