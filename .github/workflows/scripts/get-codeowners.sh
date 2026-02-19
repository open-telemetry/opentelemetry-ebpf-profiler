#!/usr/bin/env bash
#
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# This script checks the GitHub CODEOWNERS file for any code owners
# of profiler components and returns a string of the code owners if it
# finds them.
#
# Modified version of https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/571fce853d044786bd41913765d1f5a813261233/.github/workflows/scripts
# Removed COMPONENT_TYPE handling
set -euo pipefail

get_codeowners() {
  # grep arguments explained:
  #   -m 1: Match the first occurrence
  #   ^: Match from the beginning of the line
  #   ${1}: Insert first argument given to this function
  #   [\/]\?: Match 0 or 1 instances of a forward slash
  #   \s: Match any whitespace character
(grep -m 1 "^${1}[\/]\?\s" .github/CODEOWNERS || true) | \
        sed 's/   */ /g' | \
        cut -f3- -d ' '
}

if [[ -z "${COMPONENT:-}" ]]; then
    echo "COMPONENT has not been set, please ensure it is set."
    exit 1
fi

OWNERS="$(get_codeowners "${COMPONENT}")"

echo "${OWNERS}"
