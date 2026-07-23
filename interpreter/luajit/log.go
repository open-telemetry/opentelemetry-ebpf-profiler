// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// logf logs luajit debugging with the prefix 'LUA_DEBUG: ` so they stick out
// from the debug firehose.
func logf(format string, args ...any) {
	log.Debugf("LUA_DEBUG: "+format, args...)
}
