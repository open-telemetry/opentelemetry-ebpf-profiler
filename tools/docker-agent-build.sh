#!/usr/bin/env bash

set -eu

# Run the agent build process inside a Docker container with appropriate
# volume mounts and environment variables.

TARGET_ARCH="${1:-}"
VERSION="${2:-}"
REVISION="${3:-}"
BUILD_TIMESTAMP="${4:-}"

HOST_GOPATH=$(go env GOPATH)
HOST_GOCACHE=$(go env GOCACHE)
WORK_DIR="/agent"
VOLUME_MOUNTS=(-v "$PWD:/agent")
ENV_VARS=()

if [ -n "$HOST_GOPATH" ]; then
	case "$PWD/" in
		"$HOST_GOPATH"/*)
			REL_PATH="${PWD#"$HOST_GOPATH"/}"
			VOLUME_MOUNTS=(-v "$HOST_GOPATH:/go")
			WORK_DIR="/go/$REL_PATH"
			ENV_VARS=(-e GOPATH=/go)
			;;
		*)
			VOLUME_MOUNTS+=(-v "$HOST_GOPATH:/go")
			ENV_VARS+=(-e GOPATH=/go)
			;;
	esac
fi

if [ -n "$HOST_GOCACHE" ]; then
	VOLUME_MOUNTS+=(-v "$HOST_GOCACHE:/tmp/go-cache")
	ENV_VARS+=(-e GOCACHE=/tmp/go-cache)
fi

docker run "${VOLUME_MOUNTS[@]}" "${ENV_VARS[@]}" -w "$WORK_DIR" -it --rm --user "$(id -u):$(id -g)" \
	otel/opentelemetry-ebpf-profiler-dev:latest \
	"make TARGET_ARCH=$TARGET_ARCH VERSION=$VERSION REVISION=$REVISION BUILD_TIMESTAMP=$BUILD_TIMESTAMP"
