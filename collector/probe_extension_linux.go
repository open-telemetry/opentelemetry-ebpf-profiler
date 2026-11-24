// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// ProbeExtension is implemented by OTel Collector extensions that provide a
// custom eBPF probe to the ebpf_profiler receiver. Implement this interface
// in an extension and reference it by component ID via probes in
// the receiver config:
//
//	receivers:
//	  ebpf_profiler:
//	    probes:
//	      - myprobe/vfs_open
//	      - mykprobe/tcp_connect
//
//	extensions:
//	  myprobe/vfs_open:
//	    symbol: vfs_open
//	  mykprobe/tcp_connect:
//	    symbol: tcp_connect
//	    mode: kretprobe
//
// The receiver calls Probe() after Start has been called on all extensions,
// then enables the returned probe on the running tracer.
type ProbeExtension interface {
	extension.Extension
	Probe() tracer.Probe
}
