#!/usr/bin/env bash
# Test the current package under a different kernel.
# Requires qemu-system-x86_64 and bluebox to be installed.

set -eu
set -o pipefail

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

readonly kernel="linux-${kernel_version}.bz"
readonly output="$(mktemp -d --suffix=-output)"
readonly kern_dir="${KERN_DIR:-ci-kernels}"

test -e "${kern_dir}/${kernel}" || {
  echo "Failed to find kernel image ${kern_dir}/${kernel}."
  exit 1
}

echo Generating initramfs
expected=0
bb_args=(-o "${output}/initramfs.cpio")
while IFS='' read -r -d '' line ; do
    bb_args+=(-e "${line}:-test.v")
    ((expected=expected+1))
done < <(find . -name '*.test' -print0)

additionalQemuArgs=""

supportKVM=$(grep -c -E 'vmx|svm' /proc/cpuinfo || echo "0")
if [ "$supportKVM" -ne 0 ]; then
  additionalQemuArgs="-enable-kvm"
fi

bluebox "${bb_args[@]}" || (echo "failed to generate initramfs"; exit 1)

echo Testing on "${kernel_version}"
$sudo qemu-system-x86_64 ${additionalQemuArgs} \
	-nographic \
	-append "console=ttyS0" \
	-monitor none \
	-serial file:"${output}/test.log" \
	-no-user-config \
	-m 4G \
	-kernel "${kern_dir}/${kernel}" \
	-initrd "${output}/initramfs.cpio"

# Dump the output of the VM run.
cat "${output}/test.log"

# Qemu will produce an escape sequence that disables line-wrapping in the terminal,
# end result being truncated output. This restores line-wrapping after the fact.
tput smam || true

passes=$(grep -c "stdout: PASS" "${output}/test.log")

if [ "$passes" -ne "$expected" ]; then
  echo "Test ${color_red}failed${color_default} on ${kernel_version}"
  EXIT_CODE=1
else
  echo "Test ${color_green}successful${color_default} on ${kernel_version}"
  EXIT_CODE=0
fi

$sudo rm -rf "${output}"

exit $EXIT_CODE
