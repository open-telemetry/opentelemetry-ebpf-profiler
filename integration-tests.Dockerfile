FROM ubuntu:24.04
# Install dependencies once
RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    qemu-system-arm \
    ipxe-qemu \
    wget \
    curl \
    git \
    make \
    golang \
    && rm -rf /var/lib/apt/lists/*
# Install bluebox
RUN go install github.com/florianl/bluebox@v0.0.1 && \
    mv /root/go/bin/bluebox /usr/local/bin/
