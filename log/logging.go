// Package log provides a public logging interface for go.opentelemetry.io/ebpf-profiler.
package log // import "go.opentelemetry.io/ebpf-profiler/log"

import (
	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

var (
	// SetLevel configures the log level for the profiler's internal logger.
	SetLevel = log.SetLevel
	// SetLogger configures the profiler's internal logger.
	SetLogger = log.SetLogger
)
