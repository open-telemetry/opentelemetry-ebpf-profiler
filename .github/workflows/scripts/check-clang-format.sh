#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0


CLANG_FORMAT="clang-format-17"
${CLANG_FORMAT} --version
${CLANG_FORMAT} -Werror --dry-run -style=file ./support/ebpf/*.[ch]
