// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Boilerplate stubs for LuaJIT implementation.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type luajitData struct {
}

type luajitInstance struct {
	interpreter.InstanceStubs
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &luajitInstance{}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

func GetLoader(_ Config) interpreter.Loader {
	return loader
}

func loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	return nil, nil
}
