#!/usr/bin/env bash
# Generates a bluebox initramfs (plus *.manifest) from the *.test binaries in
# the current directory. Usage: gen-initramfs.sh <output.cpio> [arch]

set -eu

output="${1:?expecting output cpio path as first argument}"
arch="${2:-}"

bb_args=(-o "${output}")
: > "${output%.cpio}.manifest"
if [ -n "${arch}" ]; then
    bb_args+=(-a "${arch}")
fi
while IFS='' read -r -d '' line ; do
    bb_args+=(-e "${line}:-test.v")
    echo "${line##*/}" >> "${output%.cpio}.manifest"
done < <(find . -name '*.test' -print0 | sort -z)

# GOARCH= keeps bluebox itself running on the host despite a cross GOARCH.
GOARCH= go run github.com/florianl/bluebox@v0.0.1 "${bb_args[@]}"
