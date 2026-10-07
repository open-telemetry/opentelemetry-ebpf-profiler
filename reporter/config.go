// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"time"

	"google.golang.org/grpc"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type Config struct {
	// Name defines the name of the agent.
	Name string

	// Version defines the version of the agent.
	Version string

	// CollAgentAddr defines the destination of the backend connection.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter endpoint setting instead.
	CollAgentAddr string

	// MaxRPCMsgSize defines the maximum size of a gRPC message.
	//
	// Deprecated: only used by NewOTLP. Use an otlpexporter gRPC middleware instead.
	MaxRPCMsgSize int

	// Disable secure communication with Collection Agent.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter tls setting instead.
	DisableTLS bool

	// samplesPerSecond defines the number of samples per second.
	SamplesPerSecond int

	// Number of connection attempts to the collector after which we give up retrying.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter retry_on_failure setting instead.
	MaxGRPCRetries uint32

	// GRPCOperationTimeout is the timeout for each export request.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter timeout setting instead.
	GRPCOperationTimeout time.Duration

	// GRPCStartupBackoffTime is the time between connection attempts on startup.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter retry_on_failure setting instead.
	GRPCStartupBackoffTime time.Duration

	// GRPCConnectionTimeout is the timeout for establishing the connection.
	//
	// Deprecated: only used by NewOTLP.
	GRPCConnectionTimeout time.Duration

	ReportInterval time.Duration
	ReportJitter   float64

	// gRPCInterceptor is the client gRPC interceptor, e.g., for sending gRPC metadata.
	//
	// Deprecated: only used by NewOTLP. Use the otlpexporter headers, auth or middlewares settings instead.
	GRPCClientInterceptor grpc.UnaryClientInterceptor

	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer

	// GRPCDialOptions allows passing additional gRPC dial options when establishing
	// the connection to the collector. These options are appended after the default options.
	//
	// Deprecated: only used by NewOTLP. Use an otlpexporter gRPC middleware instead.
	GRPCDialOptions []grpc.DialOption
}
