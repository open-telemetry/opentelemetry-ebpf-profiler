package log // import "go.opentelemetry.io/ebpf-profiler/internal/log"

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

// programLevel controls the minimum log level for all loggers.
var programLevel = new(slog.LevelVar) // Info by default

// globalLogger holds a reference to the [slog.Logger] used within
// go.opentelemetry.io/ebpf-profiler.
//
// The default logger logs to stderr which is backed by the standard `log.Logger`
// interface. This logger will show messages at the Info Level.
var globalLogger = func() *atomic.Pointer[slog.Logger] {
	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: programLevel,
	}))

	p := new(atomic.Pointer[slog.Logger])
	p.Store(l)
	return p
}()

// SetLogger sets the global logger to l while respecting programLevel's log
// level. When default logger is overridden, SetLevel has no effect.
func SetLogger(l slog.Logger) {
	globalLogger.Store(&l)
}

// SetLevel dynamically changes the logger's log level, excluding
// those set via SetLogger.
func SetLevel(level slog.Level) {
	programLevel.Set(level)
}

// getLogger returns the global logger.
func getLogger() *slog.Logger {
	return globalLogger.Load()
}

// Info logs informational messages about the general state of the profiler.
func Info(msg string, args ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelInfo) {
		getLogger().Info(msg, args...)
	}
}

// Warn logs warnings in the profiler — not errors, but likely more important
// than informational messages.
func Warn(msg string, args ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelWarn) {
		getLogger().Warn(msg, args...)
	}
}

// Debug logs detailed debugging information about internal profiler behavior.
func Debug(msg string, args ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelDebug) {
		getLogger().Debug(msg, args...)
	}
}

// Error logs error messages about exceptional states of the profiler.
func Error(msg string, args ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelError) {
		getLogger().Error(msg, args...)
	}
}
