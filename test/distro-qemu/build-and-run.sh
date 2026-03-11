#!/bin/bash
set -ex

# Convenience wrapper: builds the initramfs and runs QEMU in one step.
# In CI, these are split into separate jobs for efficiency.
#
# Usage: QEMU_ARCH=x86_64 ./build-and-run.sh <kernel-version>

KERNEL_VERSION="${1:-5.10.217}"

INITRAMFS=$(mktemp /tmp/distro-qemu-initramfs.XXXXXX.gz)
cleanup() { rm -f "$INITRAMFS"; }
trap cleanup EXIT

./download-kernel.sh "$KERNEL_VERSION"
./build-initramfs.sh "$INITRAMFS"
./run-qemu.sh "$KERNEL_VERSION" "$INITRAMFS"
