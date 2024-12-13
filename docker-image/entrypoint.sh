#!/bin/bash

ORIG_GOPATH="/agent-go"

NEW_GOPATH="/agent/go"
GOPATH="$NEW_GOPATH"
GOCACHE="$GOPATH/.cache"
GOBIN="$GOPATH/bin"
PATH="$PATH:$GOBIN"
GOLANGCI_LINT_CACHE=$GOCACHE

# Check if /agent/go exists, and create it if not
if [ ! -d "${GOPATH}" ]; then
  mkdir -p ${GOPATH}
  mkdir -p ${GOBIN}
fi

cp --recursive $ORIG_GOPATH/bin/* $GOBIN

export GOPATH
export GOCACHE
export GOBIN
export PATH
export GOLANGCI_LINT_CACHE

git config --global --add safe.directory /agent

# Run the actual command (e.g., bash or other processes)
exec $@
