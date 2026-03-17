#!/bin/bash
set -ex

# Build an initramfs containing test binaries, shared libraries, and busybox.
# The resulting initramfs is arch-specific but kernel-independent.
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
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"

OUTPUT="${1:-initramfs.gz}"
# Make output path absolute.
case "$OUTPUT" in
    /*) ;;
    *)  OUTPUT="$(pwd)/$OUTPUT" ;;
esac

ROOTFS_DIR=$(mktemp -d /tmp/distro-qemu-rootfs.XXXXXX)
BUILD_DIR=$(mktemp -d /tmp/distro-qemu-build.XXXXXX)

cleanup() {
    rm -rf "$ROOTFS_DIR" "$BUILD_DIR"
}
trap cleanup EXIT

# Download parcagpu library + stub libcupti.
QEMU_ARCH="${QEMU_ARCH}" PARCAGPU_DIR="${PARCAGPU_DIR}" ./download-parcagpu.sh

# Determine architecture names.
case "$QEMU_ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *)       echo "Unsupported QEMU_ARCH: $QEMU_ARCH"; exit 1 ;;
esac

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

# --- Build minimal rootfs with busybox ---

echo "Building minimal rootfs with busybox..."
mkdir -p "$ROOTFS_DIR"/{bin,proc,sys,dev,tmp,usr/local/cuda/lib64}

# Install busybox and create symlinks.
BUSYBOX=$(command -v busybox)
cp "$BUSYBOX" "$ROOTFS_DIR/bin/busybox"
for cmd in sh mount umount dmesg poweroff halt reboot hostname uname \
           find head tail sleep cat grep cut echo ls mkdir ln; do
    ln -s busybox "$ROOTFS_DIR/bin/$cmd"
done

# copy_lib_deps: copy shared library dependencies of a binary into the rootfs,
# preserving the original directory structure.
copy_lib_deps() {
    local binary="$1"
    ldd "$binary" 2>/dev/null | grep -oP '/\S+' | while read -r lib; do
        [ -f "$lib" ] || continue
        # Resolve symlinks to get the real file.
        local real_lib
        real_lib=$(readlink -f "$lib")
        local dir
        dir=$(dirname "$lib")
        mkdir -p "$ROOTFS_DIR$dir"
        # Copy the real file if not already present.
        if [ ! -f "$ROOTFS_DIR$real_lib" ]; then
            mkdir -p "$ROOTFS_DIR$(dirname "$real_lib")"
            cp "$real_lib" "$ROOTFS_DIR$real_lib"
        fi
        # Recreate the symlink if the original path differs from the real path.
        if [ "$lib" != "$real_lib" ]; then
            ln -sf "$real_lib" "$ROOTFS_DIR$lib"
        fi
    done
}

# Copy test binaries and parcagpu .so into rootfs.
cp "${BUILD_DIR}"/*.test "$ROOTFS_DIR/"
cp "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/"

# Copy stub libcupti .so and libstdc++ into the RUNPATH so dlopen of
# libparcagpucupti.so can resolve its DT_NEEDED entries.
for stub in "${PARCAGPU_DIR}"/libcupti.so*; do
    [ -f "$stub" ] && cp "$stub" "$ROOTFS_DIR/usr/local/cuda/lib64/"
done
LIBSTDCXX=$(find /lib* /usr/lib* -name 'libstdc++.so.6' 2>/dev/null | head -1)
if [ -n "$LIBSTDCXX" ]; then
    local_real=$(readlink -f "$LIBSTDCXX")
    cp "$local_real" "$ROOTFS_DIR/usr/local/cuda/lib64/$(basename "$local_real")"
    ln -sf "$(basename "$local_real")" "$ROOTFS_DIR/usr/local/cuda/lib64/libstdc++.so.6"
    echo "Copied libstdc++ to RUNPATH"
fi

# Copy shared library deps for all test binaries, parcagpu, and busybox.
for bin in "${BUILD_DIR}"/*.test "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/bin/busybox"; do
    copy_lib_deps "$bin"
done

# Ensure libm.so is present (rtld test does runtime dlopen of libm).
LIBM=$(find /lib* /usr/lib* -name 'libm.so.6' 2>/dev/null | head -1)
if [ -n "$LIBM" ]; then
    copy_lib_deps "$LIBM"
    local_dir=$(dirname "$LIBM")
    mkdir -p "$ROOTFS_DIR$local_dir"
    [ -f "$ROOTFS_DIR$LIBM" ] || cp "$(readlink -f "$LIBM")" "$ROOTFS_DIR$LIBM"
fi

# Copy ld.so into the rootfs (needed as the ELF interpreter).
LDSO=$(readelf -l "${BUILD_DIR}/rtld.test" 2>/dev/null \
    | sed -n 's|.*\[\(.*\)\]|\1|p' | head -1)
if [ -n "$LDSO" ] && [ -f "$LDSO" ]; then
    mkdir -p "$ROOTFS_DIR$(dirname "$LDSO")"
    cp "$(readlink -f "$LDSO")" "$ROOTFS_DIR$LDSO"
fi

echo "Test binary dependencies:"
ldd "${BUILD_DIR}/rtld.test" || true

# Create init script.
cat << 'INIT_EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
export PATH=/bin

echo "===== Test Environment ====="
echo "Kernel: $(uname -r)"

# Mount required filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# Enable debug logging
export DEBUG_TEST=1
# Help the dynamic linker find libs in the CUDA RUNPATH.
export LD_LIBRARY_PATH=/usr/local/cuda/lib64

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
INIT_EOF
chmod +x "$ROOTFS_DIR/init"

# Pack initramfs.
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "$OUTPUT")

echo "Initramfs created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
