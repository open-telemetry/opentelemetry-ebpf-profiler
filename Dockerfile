FROM debian:testing

WORKDIR /agent

# cross_debian_arch: amd64 or arm64
# cross_pkg_arch: x86-64 or aarch64
RUN cross_debian_arch=$(uname -m | sed 's/x86_64/arm64/' | sed 's/aarch64/amd64/'); \
    cross_pkg_arch=$(uname -m | sed 's/aarch64/x86-64/' | sed 's/x86_64/aarch64/'); \
    apt-get update -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y \
    curl wget cmake dwz lsb-release software-properties-common gnupg git clang-16 llvm \
    golang unzip jq gcc-${cross_pkg_arch}-linux-gnu libc6-${cross_debian_arch}-cross && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

RUN wget -qO- https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b $(go env GOPATH)/bin v1.56.2


# gRPC dependencies
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

RUN                                                                                \
  PB_URL="https://github.com/protocolbuffers/protobuf/releases/download/v24.4/";   \
  PB_FILE="protoc-24.4-linux-$(uname -m | sed 's/aarch64/aarch_64/').zip";         \
  INSTALL_DIR="/usr/local";                                                        \
                                                                                   \
  curl -LO "$PB_URL/$PB_FILE"                                                      \
    && unzip "$PB_FILE" -d "$INSTALL_DIR" 'bin/*' 'include/*'                      \
    && chmod +xr "$INSTALL_DIR/bin/protoc"                                         \
    && find "$INSTALL_DIR/include" -type d -exec chmod +x {} \;                    \
    && find "$INSTALL_DIR/include" -type f -exec chmod +r {} \;                    \
    && rm "$PB_FILE"

# The docker image is built as root - make binaries available to user.
RUN mv /root/go/bin/* /usr/local/bin/

ENV GOPATH=/agent/go
ENV GOCACHE=/agent/.cache

RUN echo "export PATH=\"\$PATH:\$(go env GOPATH)/bin\"" >> ~/.bashrc

ENTRYPOINT ["/bin/bash", "-l", "-c"]
