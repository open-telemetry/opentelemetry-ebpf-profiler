#!/bin/bash
set -e

QEMU_ARCH="${QEMU_ARCH:-x86_64}"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"

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

echo "Downloading libparcagpucupti.so for ${QEMU_ARCH} from ghcr.io/parca-dev/parcagpu:latest..."

# Create directory
mkdir -p "${PARCAGPU_DIR}"

# Check if already exists
if [[ -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
    echo "libparcagpucupti.so already exists at ${PARCAGPU_DIR}/libparcagpucupti.so"
    exit 0
fi

# Pull and extract .so from Docker image using buildx (supports multi-arch)
echo "Pulling Docker image for ${DOCKER_PLATFORM}..."
TMPDIR=$(mktemp -d)
echo "FROM ghcr.io/parca-dev/parcagpu:latest" \
  | docker buildx build --platform "${DOCKER_PLATFORM}" \
    --quiet --pull --output="${TMPDIR}" -

# Find and copy the .so (may be versioned, e.g. libparcagpucupti.so.13)
SOFILE=$(find "${TMPDIR}" -name 'libparcagpucupti.so*' -type f | sort -V | tail -1)
if [[ -n "${SOFILE}" ]]; then
    cp "${SOFILE}" "${PARCAGPU_DIR}/libparcagpucupti.so"
else
    echo "❌ libparcagpucupti.so not found in container image"
    rm -rf "${TMPDIR}"
    exit 1
fi

rm -rf "${TMPDIR}"

if [[ -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
    echo "✅ libparcagpucupti.so downloaded successfully"
    ls -la "${PARCAGPU_DIR}/libparcagpucupti.so"
else
    echo "❌ Failed to download libparcagpucupti.so"
    exit 1
fi
