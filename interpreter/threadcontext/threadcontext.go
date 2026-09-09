// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Boilerplate stubs for the thread context implementation.
package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func GetLoader(_ Config) interpreter.Loader {
	return interpreter.NewLoader(loader, []interpreter.InterpreterResource{
		{MapName: BPFMapName},
	})
}

func loader(_ interpreter.EbpfHandler, _ *interpreter.LoaderInfo) (interpreter.Data, error) {
	return nil, nil
}

type threadcontextData struct{}

var _ interpreter.Data = &threadcontextData{}

func (d *threadcontextData) String() string {
	return "Native thread labels"
}

func (d *threadcontextData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	return &Instance{}, nil
}

func (d *threadcontextData) Unload(_ interpreter.EbpfHandler) {}

type Instance struct {
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

func (i *Instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}
