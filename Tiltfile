# Settings
APP_NAME = 'opentelemetry-ebpf-profiler'
IMAGE = 'opentelemetry-ebpf-profiler:dev'
BIN_PATH = 'otelcol-ebpf-profiler'

# -----------------------------------------------------------------------------
# Build the Go binary locally
# -----------------------------------------------------------------------------
local_resource(
    'ebpf-profiler-compile',
    'make otelcol-ebpf-profiler',
    deps=[],
)

# -----------------------------------------------------------------------------
# Build the container image
# -----------------------------------------------------------------------------
docker_build(
    ref=IMAGE,
    context='.',
    dockerfile='k8s/Dockerfile',
    only=[BIN_PATH],
)

# -----------------------------------------------------------------------------
# Kubernetes deploy
# -----------------------------------------------------------------------------
k8s_yaml('k8s/agent.yaml')

k8s_resource(
    APP_NAME,
    port_forwards=8080,   # remove if not needed
    extra_pod_selectors=[{'app': APP_NAME}],
)

