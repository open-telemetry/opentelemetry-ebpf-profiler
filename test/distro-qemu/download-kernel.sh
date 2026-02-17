#!/bin/bash
set -e

KERNEL_VERSION="${1:-5.10.217}"
QEMU_ARCH="${QEMU_ARCH:-x86_64}"
KERN_DIR="${KERN_DIR:-ci-kernels}"

# Map QEMU arch to Docker platform
case "$QEMU_ARCH" in
    x86_64)
        DOCKER_PLATFORM="linux/amd64"
        ;;
    aarch64)
        DOCKER_PLATFORM="linux/arm64"
        ;;
    *)
        echo "Unsupported architecture: $QEMU_ARCH"
        exit 1
        ;;
esac

echo "Downloading kernel ${KERNEL_VERSION} for ${QEMU_ARCH} from ghcr.io/cilium/ci-kernels..."

# Create directory
mkdir -p "${KERN_DIR}"

# Check if already exists
if [[ -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "Kernel ${KERNEL_VERSION} already exists at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    exit 0
fi

# Pull and extract kernel from Docker image using buildx (supports multi-arch)
echo "Pulling Docker image for ${DOCKER_PLATFORM}..."
echo "FROM ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}" \
  | docker buildx build --platform "${DOCKER_PLATFORM}" \
    --quiet --pull --output="${KERN_DIR}" -
mv "${KERN_DIR}/boot/" "${KERN_DIR}/${KERNEL_VERSION}/"

if [[ -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "✅ Kernel ${KERNEL_VERSION} downloaded successfully"
    ls -la "${KERN_DIR}/${KERNEL_VERSION}/"
else
    echo "❌ Failed to download kernel"
    exit 1
fi