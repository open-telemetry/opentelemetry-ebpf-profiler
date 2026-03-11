#!/bin/bash
set -ex

# Build an initramfs containing test binaries, parcagpu, and a debootstrap
# rootfs.  The resulting initramfs is arch-specific but kernel-independent.
#
# In CI the build runs on native runners (no cross-compilation needed).
# For local use, cross-compilation is supported via GOARCH + CC overrides.
#
# Usage: QEMU_ARCH=x86_64 ./build-initramfs.sh [output-path]

# Auto-detect host architecture if QEMU_ARCH not set.
case "$(uname -m)" in
    x86_64)  _default_arch="x86_64" ;;
    aarch64) _default_arch="aarch64" ;;
    *)       _default_arch="x86_64" ;;
esac
QEMU_ARCH="${QEMU_ARCH:-$_default_arch}"
DISTRO="${DISTRO:-ubuntu}"
RELEASE="${RELEASE:-jammy}"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"
CACHE_DIR="${CACHE_DIR:-/tmp/debootstrap-cache}"

OUTPUT="${1:-initramfs.gz}"
# Make output path absolute.
case "$OUTPUT" in
    /*) ;;
    *)  OUTPUT="$(pwd)/$OUTPUT" ;;
esac

ROOTFS_DIR=$(mktemp -d /tmp/distro-qemu-rootfs.XXXXXX)
BUILD_DIR=$(mktemp -d /tmp/distro-qemu-build.XXXXXX)

cleanup() {
    if [ -d "$ROOTFS_DIR" ]; then
        findmnt -o TARGET -n -l | grep "^${ROOTFS_DIR}" | sort -r | while read -r mp; do
            sudo umount "$mp" || sudo umount -l "$mp" || true
        done
        sudo rm -rf "$ROOTFS_DIR"
    fi
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

# Download parcagpu library + stub libcupti.
QEMU_ARCH="${QEMU_ARCH}" PARCAGPU_DIR="${PARCAGPU_DIR}" ./download-parcagpu.sh

# Determine architecture names.
case "$QEMU_ARCH" in
    x86_64)  DEBOOTSTRAP_ARCH="amd64" ;;
    aarch64) DEBOOTSTRAP_ARCH="arm64" ;;
    *)       echo "Unsupported QEMU_ARCH: $QEMU_ARCH"; exit 1 ;;
esac
GOARCH=$DEBOOTSTRAP_ARCH

# Choose mirror based on distro and architecture.
if [[ "$DISTRO" == "ubuntu" ]]; then
    if [[ "$DEBOOTSTRAP_ARCH" == "arm64" ]]; then
        MIRROR="http://ports.ubuntu.com/ubuntu-ports/"
    else
        MIRROR="https://archive.ubuntu.com/ubuntu/"
    fi
else
    MIRROR="http://deb.debian.org/debian/"
fi

# Create minimal rootfs with debootstrap.
echo "Running debootstrap to create $DISTRO $RELEASE rootfs for $DEBOOTSTRAP_ARCH..."
mkdir -p "$CACHE_DIR"
if ! sudo debootstrap --variant=minbase \
    --arch="$DEBOOTSTRAP_ARCH" \
    --cache-dir="$CACHE_DIR" \
    --foreign \
    --include=libstdc++6 \
    "$RELEASE" "$ROOTFS_DIR" "$MIRROR" ; then
    echo "Debootstrap failed, log follows."
    cat "$ROOTFS_DIR/debootstrap/debootstrap.log"
    exit 1
fi
sudo chown -R "$(id -u):$(id -g)" "$ROOTFS_DIR"

# Build test binaries.
echo "Building test binaries for ${GOARCH}..."
REPO_ROOT="$(cd ../.. && pwd)"
TEST_PKGS="./interpreter/rtld ./support/usdt/test ./test/cudaverify"

(
    cd "${REPO_ROOT}"
    if [ "$GOARCH" = "arm64" ] && [ "$(uname -m)" != "aarch64" ]; then
        CGO_ENABLED=1 GOARCH=${GOARCH} CC=aarch64-linux-gnu-gcc \
            go test -c -o "${BUILD_DIR}/" ${TEST_PKGS}
    else
        CGO_ENABLED=1 GOARCH=${GOARCH} \
            go test -c -o "${BUILD_DIR}/" ${TEST_PKGS}
    fi
)

# Copy test binaries and parcagpu .so into rootfs.
cp "${BUILD_DIR}"/*.test "$ROOTFS_DIR/"
cp "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/"

# Copy stub libcupti .so into the RUNPATH so the dynamic linker resolves
# the DT_NEEDED entry without a real CUDA install.
mkdir -p "$ROOTFS_DIR/usr/local/cuda/lib64"
for stub in "${PARCAGPU_DIR}"/libcupti.so*; do
    [ -f "$stub" ] && cp "$stub" "$ROOTFS_DIR/usr/local/cuda/lib64/"
done

# Copy libstdc++ into the RUNPATH so the dynamic linker finds it.
# With --foreign debootstrap the .deb is downloaded but not extracted, so we
# pull the .so directly from the .deb archive.
LIBSTDCXX_DEB=$(find "$ROOTFS_DIR" -name 'libstdc++6_*.deb' -type f | head -1)
if [ -n "$LIBSTDCXX_DEB" ]; then
    EXTRACT_TMP=$(mktemp -d)
    dpkg-deb -x "$LIBSTDCXX_DEB" "$EXTRACT_TMP"
    LIBSTDCXX_REAL=$(find "$EXTRACT_TMP" -name 'libstdc++.so.6.*' ! -name '*.py' -type f | head -1)
    if [ -n "$LIBSTDCXX_REAL" ]; then
        cp "$LIBSTDCXX_REAL" "$ROOTFS_DIR/usr/local/cuda/lib64/"
        ln -sf "$(basename "$LIBSTDCXX_REAL")" "$ROOTFS_DIR/usr/local/cuda/lib64/libstdc++.so.6"
        echo "Copied $(basename "$LIBSTDCXX_REAL") + symlink to RUNPATH from deb"
    fi
    rm -rf "$EXTRACT_TMP"
else
    LIBSTDCXX_REAL=$(find "$ROOTFS_DIR" -name 'libstdc++.so.6.*' ! -name '*.py' -type f | head -1)
    if [ -n "$LIBSTDCXX_REAL" ]; then
        cp "$LIBSTDCXX_REAL" "$ROOTFS_DIR/usr/local/cuda/lib64/"
        ln -sf "$(basename "$LIBSTDCXX_REAL")" "$ROOTFS_DIR/usr/local/cuda/lib64/libstdc++.so.6"
        echo "Copied $(basename "$LIBSTDCXX_REAL") + symlink to RUNPATH"
    fi
fi

echo "Test binary dependencies:"
ldd "${BUILD_DIR}/rtld.test" || true

# Create init script.
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

# Rebuild ld.so cache so the linker finds libraries in multiarch paths.
ldconfig 2>/dev/null || true

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
    echo "===== BPF dmesg ====="
    dmesg | tail -60
    echo "===== TEST FAILED (exit code: $RESULT) ====="
fi

sleep 1
echo o > /proc/sysrq-trigger 2>/dev/null
sleep 1
poweroff -f 2>/dev/null || halt -f
EOF
chmod +x "$ROOTFS_DIR/init"

# Pack initramfs.
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "$OUTPUT")

echo "Initramfs created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
