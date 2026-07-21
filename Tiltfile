# Settings
APP_NAME = 'opentelemetry-ebpf-profiler'
IMAGE = 'opentelemetry-ebpf-profiler:dev'
BIN_PATH = 'otelcol-ebpf-profiler'
OTEL_CONFIG_PATH = './cmd/otelcol-ebpf-profiler/local.example.yaml'

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
# Generate ConfigMap from the local configuration file
# -----------------------------------------------------------------------------
otel_config_map = {
    'apiVersion': 'v1',
    'kind': 'ConfigMap',
    'metadata': {
        'name': 'otel-collector-config',
    },
    'data': {
        'otel-collector-config.yaml': str(
            read_file(OTEL_CONFIG_PATH)
        ),
    },
}

k8s_yaml(encode_yaml(otel_config_map))

# -----------------------------------------------------------------------------
# Kubernetes deploy
# -----------------------------------------------------------------------------
k8s_yaml('k8s/agent.yaml')

k8s_resource(
    APP_NAME,
    port_forwards=8080,   # remove if not needed
    extra_pod_selectors=[{'app': APP_NAME}],
)

