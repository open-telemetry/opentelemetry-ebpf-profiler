// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"google.golang.org/grpc"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestReportOTLPProfile(t *testing.T) {
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)

	pi := &protoImpl{}
	s := grpc.NewServer()
	pprofileotlp.RegisterGRPCServer(s, pi)
	go func() {
		_ = s.Serve(lis)
	}()

	r, err := NewOTLP(&Config{
		CollAgentAddr:            lis.Addr().String(),
		CGroupCacheElements:      1,
		SamplesPerSecond:         1,
		ExecutablesCacheElements: 1,
		FramesCacheElements:      1,
		ReportInterval:           time.Millisecond,
		MaxRPCMsgSize:            32 << 20, // 32 MiB
		GRPCStartupBackoffTime:   2,
		GRPCConnectionTimeout:    time.Second,
		GRPCOperationTimeout:     time.Second,
		DisableTLS:               true,
	})
	require.NoError(t, err)

	require.NoError(t, r.Start(context.Background()))

	r.ReportTraceEvent(&libpf.Trace{}, &TraceEventMeta{})

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, pi.exportCount)
	}, time.Second, time.Millisecond, "the grpc server should have received an export request")

	defer r.Stop()
}

type protoImpl struct {
	pprofileotlp.UnimplementedGRPCServer

	exportCount int
}

func (pi *protoImpl) Export(context.Context, pprofileotlp.ExportRequest) (pprofileotlp.ExportResponse, error) {
	pi.exportCount++
	return pprofileotlp.NewExportResponse(), nil
}
