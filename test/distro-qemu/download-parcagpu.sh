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

# Create directory
mkdir -p "${PARCAGPU_DIR}"

# Download libparcagpucupti.so if not already present.
if [[ ! -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
    echo "Downloading libparcagpucupti.so for ${QEMU_ARCH} from ghcr.io/parca-dev/parcagpu:latest..."

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

    if [[ ! -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
        echo "❌ Failed to download libparcagpucupti.so"
        exit 1
    fi

    echo "✅ libparcagpucupti.so downloaded successfully"
    ls -la "${PARCAGPU_DIR}/libparcagpucupti.so"
fi

# Build a stub libcupti .so so that dlopen of libparcagpucupti.so succeeds
# without a real CUDA installation.  The stub only needs to satisfy the
# DT_NEEDED file lookup — the actual CUPTI symbols are provided by
# mock_cupti.c in the test binary (exported via --export-dynamic).
CUPTI_SONAME=$(readelf -d "${PARCAGPU_DIR}/libparcagpucupti.so" \
    | sed -n 's/.*NEEDED.*\[\(libcupti\.so[^]]*\)\].*/\1/p')

if [[ -n "${CUPTI_SONAME}" && ! -f "${PARCAGPU_DIR}/${CUPTI_SONAME}" ]]; then
    STUB_C=$(mktemp --suffix=.c)
    echo "void __cupti_stub(void){}" > "${STUB_C}"

    # Determine cross-compiler for the target arch.
    case "$QEMU_ARCH" in
        aarch64) STUB_CC="${CC:-aarch64-linux-gnu-gcc}" ;;
        *)       STUB_CC="${CC:-cc}" ;;
    esac

    ${STUB_CC} -shared -o "${PARCAGPU_DIR}/${CUPTI_SONAME}" \
        -Wl,-soname,"${CUPTI_SONAME}" "${STUB_C}"
    rm -f "${STUB_C}"
    echo "✅ Built stub ${CUPTI_SONAME}"
fi
