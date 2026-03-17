#!/bin/bash
set -ex

# Run tests in QEMU with a pre-built initramfs and a specific kernel.
#
# Usage: QEMU_ARCH=x86_64 ./run-qemu.sh <kernel-version> [initramfs-path]

# Auto-detect host architecture if QEMU_ARCH not set.
case "$(uname -m)" in
    x86_64)  _default_arch="x86_64" ;;
    aarch64) _default_arch="aarch64" ;;
    *)       _default_arch="x86_64" ;;
esac
QEMU_ARCH="${QEMU_ARCH:-$_default_arch}"
KERN_DIR="${KERN_DIR:-ci-kernels}"

KERNEL_VERSION="${1:?Usage: run-qemu.sh <kernel-version> [initramfs-path]}"
INITRAMFS="${2:-initramfs.gz}"

# Validate inputs.
if [[ ! -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "ERROR: Kernel not found at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    exit 1
fi
if [[ ! -f "$INITRAMFS" ]]; then
    echo "ERROR: Initramfs not found at $INITRAMFS"
    exit 1
fi

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    sudo="sudo"
fi

# Determine KVM and arch-specific QEMU args.
additionalQemuArgs=""
supportKVM=$(grep -E 'vmx|svm' /proc/cpuinfo || true)
if [ "$supportKVM" ] && [ "$QEMU_ARCH" = "$(uname -m)" ]; then
    additionalQemuArgs="-enable-kvm"
fi

case "$QEMU_ARCH" in
    x86_64)
        CONSOLE_ARG="console=ttyS0"
        ;;
    aarch64)
        additionalQemuArgs+=" -machine virt -cpu max"
        CONSOLE_ARG="console=ttyAMA0"
        ;;
esac

echo ""
echo "===== Starting QEMU with kernel ${KERNEL_VERSION} on ${QEMU_ARCH} ====="
echo ""

# Run QEMU and capture output.
QEMU_OUTPUT=$(mktemp)
${sudo} qemu-system-${QEMU_ARCH} ${additionalQemuArgs} \
    -nographic \
    -monitor none \
    -serial mon:stdio \
    -m 2G \
    -kernel "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" \
    -initrd "$INITRAMFS" \
    -append "${CONSOLE_ARG} init=/init quiet loglevel=3" \
    -no-reboot \
    -display none \
    | tee "$QEMU_OUTPUT"

# Parse output for test result.
if grep -q "===== TEST PASSED =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test completed successfully"
    exit 0
elif grep -q "===== TEST FAILED" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test failed"
    exit 1
elif grep -q "===== TEST TIMED OUT =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test timed out"
    exit 124
else
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Could not determine test result (QEMU may have crashed)"
    exit 2
fi
