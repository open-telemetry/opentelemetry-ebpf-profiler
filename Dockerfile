FROM debian:testing

WORKDIR /agent

ARG arch=amd64

RUN apt-get update -y && apt-get dist-upgrade -y && apt-get install -y \
    curl wget cmake dwz lsb-release software-properties-common gnupg git clang llvm \
    golang unzip

RUN git clone --depth 1 --branch v3.1.0 --recursive https://github.com/zyantific/zydis.git && \
    cd zydis && mkdir build && cd build && \
    cmake -DZYDIS_BUILD_EXAMPLES=OFF .. && make -j$(nproc) && make install && \
    cd zycore && make install && \
    cd ../../.. && rm -rf zydis

RUN wget -qO- https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2


# gRPC dependencies
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

RUN                                                                                \
  PB_URL="https://github.com/protocolbuffers/protobuf/releases/download/v24.4/";   \
  PB_FILE="protoc-24.4-linux-x86_64.zip";                                      \
  INSTALL_DIR="/usr/local";                                                        \
                                                                                   \
  curl -LO "$PB_URL/$PB_FILE"                                                      \
    && unzip "$PB_FILE" -d "$INSTALL_DIR" 'bin/*' 'include/*'                      \
    && chmod +xr "$INSTALL_DIR/bin/protoc"                                         \
    && find "$INSTALL_DIR/include" -type d -exec chmod +x {} \;                    \
    && find "$INSTALL_DIR/include" -type f -exec chmod +r {} \;                    \
    && rm "$PB_FILE"

RUN echo "export PATH=\"\$PATH:\$(go env GOPATH)/bin\"" >> ~/.bashrc

ENTRYPOINT ["/bin/bash", "-l", "-c"]
