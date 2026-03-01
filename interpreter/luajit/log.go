// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Set this to true when LUA_DEBUG env var is set.
var development bool

func init() {
	_, dbgEnv := os.LookupEnv("LUA_DEBUG")
	development = dbgEnv
}

// logf logs luajit debugging as higher level so they stick out w/o
// enabling debug firehose if LUA_DEBUG env var is set.
func logf(format string, args ...interface{}) {
	if development {
		logrus.Infof(format, args...)
	} else {
		logrus.Debugf(format, args...)
	}
}
