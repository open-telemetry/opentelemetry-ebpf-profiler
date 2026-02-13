#!/bin/bash
set -ex

# Configuration
KERNEL_VERSION="${1:-5.10.217}"
QEMU_ARCH="${QEMU_ARCH:-x86_64}"
DISTRO="${DISTRO:-ubuntu}"  # debian or ubuntu
RELEASE="${RELEASE:-jammy}"  # jammy/noble for ubuntu (with USDT probes), bullseye for debian
ROOTFS_DIR="rootfs"
OUTPUT_DIR="output"
KERN_DIR="${KERN_DIR:-ci-kernels}"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"
CACHE_DIR="${CACHE_DIR:-/tmp/debootstrap-cache}"

# Download parcagpu library
PARCAGPU_DIR="${PARCAGPU_DIR}" ./download-parcagpu.sh

echo "Building rootfs with $DISTRO $RELEASE..."

# Clean up previous builds
# First, unmount any leftover mounts from previous debootstrap runs
if [ -d "$ROOTFS_DIR" ]; then
    echo "Cleaning up any mounted filesystems in $ROOTFS_DIR..."
    # Find all mount points under ROOTFS_DIR and unmount them in reverse order (deepest first)
    findmnt -o TARGET -n -l | grep "^$(pwd)/$ROOTFS_DIR" | sort -r | while read -r mountpoint; do
        echo "  Unmounting $mountpoint"
        sudo umount "$mountpoint" || sudo umount -l "$mountpoint" || true
    done
fi

sudo rm -rf "$ROOTFS_DIR" "$OUTPUT_DIR"
mkdir -p "$ROOTFS_DIR" "$OUTPUT_DIR" "$CACHE_DIR"

# Determine debootstrap architecture
DEBOOTSTRAP_ARCH="amd64"
case "$QEMU_ARCH" in
    x86_64)
        DEBOOTSTRAP_ARCH="amd64"
        ;;
    aarch64)
        DEBOOTSTRAP_ARCH="arm64"
        ;;
    *)
        echo "Unsupported QEMU_ARCH: $QEMU_ARCH"
        exit 1
        ;;
esac

GOARCH=$DEBOOTSTRAP_ARCH

# Choose mirror based on distro and architecture
if [[ "$DISTRO" == "ubuntu" ]]; then
    # Ubuntu ARM64 packages are on ports.ubuntu.com
    if [[ "$DEBOOTSTRAP_ARCH" == "arm64" ]]; then
        MIRROR="http://ports.ubuntu.com/ubuntu-ports/"
    else
        MIRROR="http://mirrors.layeronline.com/ubuntu/"
    fi
else
    MIRROR="http://deb.debian.org/debian/"
fi

# Create minimal rootfs with debootstrap (requires sudo for chroot operations)
echo "Running debootstrap to create $DISTRO $RELEASE rootfs for $DEBOOTSTRAP_ARCH..."
sudo debootstrap --variant=minbase \
    --arch="$DEBOOTSTRAP_ARCH" \
    --cache-dir="$CACHE_DIR" \
    "$RELEASE" "$ROOTFS_DIR" "$MIRROR" || cat "$ROOTFS_DIR/debootstrap/debootstrap.log"

# Change ownership of rootfs to current user to avoid needing sudo for subsequent operations
sudo chown -R "$(id -u):$(id -g)" "$ROOTFS_DIR"

# Build the test binary (must be dynamic for dlopen to work)
echo "Building test binary for $DISTRO $RELEASE $DEBOOTSTRAP_ARCH..."

# For cross-compilation or Ubuntu jammy/noble, local build works (host has compatible or newer glibc)
# For older distros, would need Docker build (disabled by default for speed)
if [[ "${USE_DOCKER}" == "1" ]] && command -v docker &> /dev/null; then
    # Determine base image
    if [[ "$DISTRO" == "ubuntu" ]]; then
        BASE_IMAGE="ubuntu:${RELEASE}"
    else
        BASE_IMAGE="debian:${RELEASE}"
    fi

    # Build in container to match target glibc (slow, downloads Go)
    echo "Using Docker to build with matching glibc version..."
    docker run --rm \
        -v "$(pwd)/../..:/workspace" \
        -w /workspace/test/distro-qemu \
        --platform "linux/${DEBOOTSTRAP_ARCH}" \
        "$BASE_IMAGE" \
        bash -c "apt-get update -qq && apt-get install -y -qq wget libc6-dev gcc > /dev/null 2>&1 && \
                 wget -q https://go.dev/dl/go1.24.7.linux-${GOARCH}.tar.gz && \
                 tar -C /usr/local -xzf go1.24.7.linux-${GOARCH}.tar.gz && \
                 export PATH=/usr/local/go/bin:\$PATH && \
                 CGO_ENABLED=1 go test -c ../../interpreter/rtld ../../support/usdt/test ../../test/cudaverify"
else
    # Local build with cross-compilation if needed
    echo "Building locally for ${GOARCH}..."
    if [ "$GOARCH" = "arm64" ]; then
        # Cross-compile for ARM64 using aarch64-linux-gnu-gcc
        CGO_ENABLED=1 GOARCH=${GOARCH} CC=aarch64-linux-gnu-gcc go test -c ../../interpreter/rtld ../../support/usdt/test ../../test/cudaverify
    else
        CGO_ENABLED=1 GOARCH=${GOARCH} go test -c ../../interpreter/rtld ../../support/usdt/test ../../test/cudaverify
    fi
fi

# Copy test binaries into rootfs
cp *.test "$ROOTFS_DIR/"

# Copy parcagpu .so into rootfs
cp "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/"

# List dynamic dependencies for debugging
echo "Test binary dependencies:"
ldd rtld.test || true

# Create init script
cat << 'EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
echo "===== Test Environment ====="
echo "Kernel: $(uname -r)"
echo "Hostname: $(hostname)"

# Find and display ld.so info
LDSO=$(find /lib* /usr/lib* -name 'ld-linux*' -o -name 'ld-*.so*' 2>/dev/null | head -1)
echo "ld.so location: $LDSO"
if [ -n "$LDSO" ]; then
    echo "ld.so version: $($LDSO --version | head -1)"
fi

# Find libm for dlopen test
LIBM=$(find /lib* /usr/lib* -name 'libm.so*' 2>/dev/null | head -1)
echo "libm.so location: $LIBM"

echo "================================="

# Mount required filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# Enable debug logging
export DEBUG_TEST=1

# Run the tests
echo ""
/rtld.test -test.v && /test.test -test.v && /cudaverify.test -test.v -so-path=/libparcagpucupti.so
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo ""
    echo "===== TEST PASSED ====="
elif [ $RESULT -eq 137 ] || [ $RESULT -eq 124 ]; then
    echo ""
    echo "===== TEST TIMED OUT ====="
else
    echo ""
    echo "===== TEST FAILED (exit code: $RESULT) ====="
fi

# Give time to see output before shutdown
sleep 1

# Try to cleanly shutdown QEMU
# The sysrq 'o' trigger will power off the system
echo o > /proc/sysrq-trigger 2>/dev/null

# If sysrq doesn't work, force halt
sleep 1
poweroff -f 2>/dev/null || halt -f
EOF
chmod +x "$ROOTFS_DIR/init"

# Create initramfs
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "../$OUTPUT_DIR/initramfs.gz")

echo "Rootfs created: $OUTPUT_DIR/initramfs.gz ($(du -h $OUTPUT_DIR/initramfs.gz | cut -f1))"

# Check if kernel exists
if [[ ! -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo ""
    echo "ERROR: Kernel ${KERNEL_VERSION} not found at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    echo ""
    echo "To download kernel images:"
    echo "  mkdir -p ci-kernels"
    echo "  docker pull ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}"
    echo "  docker create --name kernel-extract ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}"
    echo "  docker cp kernel-extract:/boot ci-kernels/${KERNEL_VERSION}"
    echo "  docker rm kernel-extract"
    echo ""
    exit 1
fi

# Use sudo if /dev/kvm isn't accessible by the current user
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi

# Determine additional QEMU args based on architecture
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

# Run QEMU and capture output
QEMU_OUTPUT=$(mktemp)
${sudo} qemu-system-${QEMU_ARCH} ${additionalQemuArgs} \
    -nographic \
    -monitor none \
    -serial mon:stdio \
    -m 2G \
    -kernel "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" \
    -initrd "$OUTPUT_DIR/initramfs.gz" \
    -append "${CONSOLE_ARG} init=/init quiet loglevel=3" \
    -no-reboot \
    -display none \
    | tee "$QEMU_OUTPUT"

# Parse output for test result
if grep -q "===== TEST PASSED =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "✅ Test completed successfully"
    exit 0
elif grep -q "===== TEST FAILED" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "❌ Test failed"
    exit 1
elif grep -q "===== TEST TIMED OUT =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "❌ Test timed out"
    exit 124
else
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "❌ Could not determine test result (QEMU may have crashed)"
    exit 2
fi