// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"os"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// Set this to true when LUA_DEBUG env var is set.
var development bool

func init() {
	_, dbgEnv := os.LookupEnv("LUA_DEBUG")
	development = dbgEnv
}

// logf logs luajit debugging as higher level so they stick out w/o
// enabling debug firehose if LUA_DEBUG env var is set.
func logf(format string, args ...any) {
	if development {
		log.Infof(format, args...)
	} else {
		log.Debugf(format, args...)
	}
}
