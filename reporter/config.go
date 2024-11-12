// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"google.golang.org/grpc"
)

type Config struct {
	// Name defines the name of the agent.
	Name string

	// Version defines the version of the agent.
	Version string

	// CollAgentAddr defines the destination of the backend connection.
	CollAgentAddr string

	// MaxRPCMsgSize defines the maximum size of a gRPC message.
	MaxRPCMsgSize int

	// Disable secure communication with Collection Agent.
	DisableTLS bool
	// ExecutablesCacheElements defines item capacity of the executables cache.
	ExecutablesCacheElements uint32
	// FramesCacheElements defines the item capacity of the frames cache.
	FramesCacheElements uint32
	// CGroupCacheElements defines the item capacity of the cgroup cache.
	CGroupCacheElements uint32
	// samplesPerSecond defines the number of samples per second.
	SamplesPerSecond int
	// HostID is the host ID to be sent to the collection agent.
	HostID uint64
	// KernelVersion is the kernel version of the host.
	KernelVersion string
	// HostName is the name of the host.
	HostName string
	// IPAddress is the IP address of the host.
	IPAddress string

	// Number of connection attempts to the collector after which we give up retrying.
	MaxGRPCRetries uint32

	GRPCOperationTimeout   time.Duration
	GRPCStartupBackoffTime time.Duration
	GRPCConnectionTimeout  time.Duration
	ReportInterval         time.Duration

	// gRPCInterceptor is the client gRPC interceptor, e.g., for sending gRPC metadata.
	GRPCClientInterceptor grpc.UnaryClientInterceptor

	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd SampleAttrProducer
}

// SampleAttrProducer provides a hook point to:
//
// - inspect each trace and its meta when it is enqueued in the reporter
// - produce extra meta info
// - attach extra attributes to the trace
type SampleAttrProducer interface {
	// CollectExtraSampleMeta gathers extra sample meta-info and returns it as
	// a pointer to a **hashable** struct.
	CollectExtraSampleMeta(trace *libpf.Trace, meta *TraceEventMeta) any

	// ExtraSampleAttrs is called when the reporter populates the Sample struct
	// before sending it out. Attributes returned from this function are added
	// as Sample attributes. `meta` receives the pointer that was returned from
	// CollectExtraSampleMeta.
	ExtraSampleAttrs(attrMgr *AttrTableManager, meta any) []AttrIndex
}
