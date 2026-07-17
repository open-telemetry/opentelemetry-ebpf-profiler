FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bin/otelcol-ebpf-profiler /app/ebpf-agent-local

ENTRYPOINT ["/app/ebpf-agent-local"]
