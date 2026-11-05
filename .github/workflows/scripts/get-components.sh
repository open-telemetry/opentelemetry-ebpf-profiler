#!/usr/bin/env sh
#
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Get a list of components within the repository that have some form of ownership
# ascribed to them.
#
# Copy of https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/571fce853d044786bd41913765d1f5a813261233/.github/workflows/scripts 
grep -E '^[A-Za-z0-9/]' .github/CODEOWNERS | \
    awk '{ print $1 }' | \
    sed -E 's%(.+)/$%\1%'
