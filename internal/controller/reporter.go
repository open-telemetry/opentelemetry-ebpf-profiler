package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"context"

	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// startReporter sets up the reporter on the controller
func (c *Controller) startReporter(ctx context.Context, intervals *times.Times,
	traceHandlerCacheSize uint32, kernelVersion, hostname, sourceIP string) error {
	if c.reporter != nil {
		return nil
	}

	rep, err := reporter.Start(ctx, &reporter.Config{
		CollAgentAddr:          c.config.CollAgentAddr,
		DisableTLS:             c.config.DisableTLS,
		MaxRPCMsgSize:          32 << 20, // 32 MiB
		MaxGRPCRetries:         5,
		GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
		ReportInterval:         intervals.ReportInterval(),
		CacheSize:              traceHandlerCacheSize,
		SamplesPerSecond:       c.config.SamplesPerSecond,
		KernelVersion:          kernelVersion,
		HostName:               hostname,
		IPAddress:              sourceIP,
	})
	if err != nil {
		return err
	}
	c.reporter = rep

	return nil
}
