FROM debian:testing

WORKDIR /agent

RUN apt-get update -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y clang-16 git lld-16 make pkgconf unzip wget && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

COPY go.mod /tmp/go.mod
# Extract Go version from go.mod
RUN GO_VERSION=$(grep -oPm1 '^go \K([[:digit:].]+)' /tmp/go.mod) && \
    GOARCH=$(uname -m) && if [ "$GOARCH" = "x86_64" ]; then GOARCH=amd64; elif [ "$GOARCH" = "aarch64" ]; then GOARCH=arm64; fi && \
    wget -qO- https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz | tar -C /usr/local -xz

# Set Go environment variables
ENV GOPATH="/agent/go"
ENV GOCACHE="/agent/.cache"
ENV PATH="/usr/local/go/bin:$PATH"

# gRPC dependencies
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

RUN                                                                                \
  PB_URL="https://github.com/protocolbuffers/protobuf/releases/download/v24.4/";   \
  PB_FILE="protoc-24.4-linux-x86_64.zip";                                      \
  INSTALL_DIR="/usr/local";                                                        \
                                                                                   \
  wget -q "$PB_URL/$PB_FILE"                                                       \
    && unzip "$PB_FILE" -d "$INSTALL_DIR" 'bin/*' 'include/*'                      \
    && chmod +xr "$INSTALL_DIR/bin/protoc"                                         \
    && find "$INSTALL_DIR/include" -type d -exec chmod +x {} \;                    \
    && find "$INSTALL_DIR/include" -type f -exec chmod +r {} \;                    \
    && rm "$PB_FILE"

# Append to /etc/profile for login shells
RUN echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile

ENTRYPOINT ["/bin/bash", "-l", "-c"]
