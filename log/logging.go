// Package log provides a public logging interface for go.opentelemetry.io/ebpf-profiler.
package log // import "go.opentelemetry.io/ebpf-profiler/log"

import (
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// SetLevel configures the log level for the profiler's internal logger.
func SetLevel(level slog.Level) {
	log.SetLevelLogger(level)
}

// SetLogger configures the profiler's internal logger.
func SetLogger(l slog.Logger) {
	log.SetLogger(l)
}
