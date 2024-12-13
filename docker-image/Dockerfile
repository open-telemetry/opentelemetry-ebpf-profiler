FROM delivery.instana.io/int-docker-private-virtual/ubuntu:22.04

WORKDIR /agent-go

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        ca-certificates \
        gnupg2 \
        software-properties-common \
        wget \
        xz-utils \
        git \
        findutils \
        unzip \
        make \
        binutils \
        build-essential

RUN wget -O clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04.tar.xz \
    https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04.tar.xz \
    && tar -xvf clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04.tar.xz -C /opt

ENV PATH="/opt/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin:$PATH"

#RUN microdnf update -y \
#    && microdnf install -y llvm-toolset git unzip wget \
#    && microdnf install -y tar gzip unzip findutils lld
#
#RUN microdnf clean all -y

COPY go.mod /tmp/go.mod
# Extract Go version from go.mod
RUN GO_VERSION=$(grep -oPm1 '^go \K([[:digit:].]+)' /tmp/go.mod) && \
    GOARCH=$(uname -m) && if [ "$GOARCH" = "x86_64" ]; then GOARCH=amd64; elif [ "$GOARCH" = "aarch64" ]; then GOARCH=arm64; fi && \
    wget https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    tar -C /usr/local -xvzf ./go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    rm -rf ./go${GO_VERSION}.linux-${GOARCH}.tar.gz

# Set Go environment variables
ENV GOPATH="/agent-go"
ENV GOCACHE="$GOPATH/.cache"
ENV GOBIN="$GOPATH/bin"
# not addin GOBIN on purpose, see entrypoint
ENV PATH="/usr/local/go/bin:$PATH"

# gRPC dependencies
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
RUN go install github.com/jcchavezs/porto/cmd/porto@v0.6.0
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.1

RUN                                                                                \
  PB_URL="https://github.com/protocolbuffers/protobuf/releases/download/v24.4/";   \
  PB_FILE="protoc-24.4-linux-x86_64.zip";                                          \
  INSTALL_DIR="/usr/local";                                                        \
                                                                                   \
  wget -q "$PB_URL/$PB_FILE"                                                       \
    && unzip "$PB_FILE" -d "$INSTALL_DIR" 'bin/*' 'include/*'                      \
    && chmod +xr "$INSTALL_DIR/bin/protoc"                                         \
    && find "$INSTALL_DIR/include" -type d -exec chmod +x {} \;                    \
    && find "$INSTALL_DIR/include" -type f -exec chmod +r {} \;                    \
    && rm "$PB_FILE"

# Append to /etc/profile for login shells
RUN echo 'export PATH="$PATH"' >> /etc/profile

WORKDIR /agent

COPY docker-image/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
