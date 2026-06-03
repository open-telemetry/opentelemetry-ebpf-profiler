#!/usr/bin/env bash
# Test the current package under a different kernel.
# Requires qemu-system-$QEMU_ARCH and bluebox to be installed.

set -eu
set -o pipefail

qemu_arch="${QEMU_ARCH:-x86_64}"
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

readonly output="$(mktemp -d --suffix=-output)"
readonly kern_dir="${KERN_DIR:-ci-kernels}"

test -e "${kern_dir}/${kernel_version}/vmlinuz" || {
  echo "Failed to find kernel image ${kern_dir}/${kernel_version}/vmlinuz."
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

supportKVM=$(grep -E 'vmx|svm' /proc/cpuinfo || true)
if [ ! "$supportKVM" ] && [ "$qemu_arch" = "$(uname -m)" ]; then
  additionalQemuArgs="-enable-kvm"
fi

case "$qemu_arch" in
    x86_64)
        additionalQemuArgs+=" -append console=ttyS0"
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

# When INCLUDE_LIBC=1, append the host's glibc shared libraries and dynamic
# linker into the initramfs at their canonical paths. This is required for
# tests that need a real, dynamically linked libc inside the guest -- in
# particular the rtld dlopen-uprobe integration test, which calls dlopen()
# from cgo. bluebox produces a statically linked initramfs and would
# otherwise carry no libc.
if [[ -n "${INCLUDE_LIBC:-}" ]]; then
  # Per-arch bundling: interp_path is the canonical PT_INTERP path baked into
  # test ELFs (must exist verbatim inside the initramfs or exec returns
  # ENOENT). lib_target_dir is where to place the other shared libraries in
  # the initramfs (the matching multiarch directory the target's ld.so
  # searches). search_roots is where to find these on the runner -- which
  # may differ from the target arch when amd64 CI hosts cross-targeting
  # arm64 (libs come from libc6-arm64-cross under /usr/aarch64-linux-gnu/lib).
  case "${qemu_arch}" in
    x86_64)
      ld_pattern='ld-linux-x86-64.so*'
      interp_path='/lib64/ld-linux-x86-64.so.2'
      lib_target_dir='/lib/x86_64-linux-gnu'
      search_roots=(/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
                    /lib /usr/lib /lib64 /usr/lib64)
      ;;
    aarch64)
      ld_pattern='ld-linux-aarch64.so*'
      interp_path='/lib/ld-linux-aarch64.so.1'
      lib_target_dir='/lib/aarch64-linux-gnu'
      search_roots=(/usr/aarch64-linux-gnu/lib
                    /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu)
      ;;
    *)
      echo "INCLUDE_LIBC: unsupported arch ${qemu_arch}"
      exit 1
      ;;
  esac

  # find_in_roots <name> <out-var>: locate the first match of <name> across
  # the configured search_roots and store the absolute path in <out-var>.
  # Uses -print -quit (returns 0 with empty output on no match) to avoid the
  # `| head -1` pipeline that interacts badly with `set -o pipefail` when
  # the search yields nothing.
  find_in_roots() {
    local pattern="$1" outvar="$2" found="" root candidate
    for root in "${search_roots[@]}"; do
      [[ -d "${root}" ]] || continue
      candidate=$(find -L "${root}" -maxdepth 2 -name "${pattern}" \
        -print -quit 2>/dev/null || true)
      if [[ -n "${candidate}" ]]; then
        found="${candidate}"
        break
      fi
    done
    printf -v "${outvar}" '%s' "${found}"
  }

  libc_staging=$(mktemp -d)
  mkdir -p "${libc_staging}${lib_target_dir}"
  mkdir -p "${libc_staging}$(dirname "${interp_path}")"

  for lib in libc.so.6 libm.so.6 libdl.so.2 libpthread.so.0; do
    find_in_roots "${lib}" src
    if [[ -z "${src}" ]]; then
      echo "INCLUDE_LIBC: missing ${lib} for ${qemu_arch} (searched: ${search_roots[*]})"
      exit 1
    fi
    cp -L "${src}" "${libc_staging}${lib_target_dir}/${lib}"
  done

  find_in_roots "${ld_pattern}" ldso
  if [[ -z "${ldso}" ]]; then
    echo "INCLUDE_LIBC: missing dynamic linker matching ${ld_pattern} for ${qemu_arch} (searched: ${search_roots[*]})"
    exit 1
  fi
  cp -L "${ldso}" "${libc_staging}${interp_path}"

  # Concatenate a fresh cpio archive of the libc bits onto bluebox's
  # initramfs. The kernel parses sequential cpio archives in a single
  # initramfs file. `cpio -A` rewrites the existing archive and has been
  # observed to silently drop entries here; manual concatenation is more
  # robust.
  (cd "${libc_staging}" && find . -mindepth 1 \
    | cpio -o -H newc 2>/dev/null) >> "${output}/initramfs.cpio"
  rm -rf "${libc_staging}"
fi

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
if [ "$TERM" ]; then
  tput smam || true
fi

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
