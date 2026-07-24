package log // import "go.opentelemetry.io/ebpf-profiler/internal/log"

import (
	"context"
	"errors"
	"fmt"
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

// Infof logs informational messages about the general state of the profiler.
// This function is a wrapper around the structured slog-based logger,
// formatting the message as a string for backward compatibility with
// previous unstructured logging.
func Infof(msg string, keysAndValues ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelInfo) {
		getLogger().Info(fmt.Sprintf(msg, keysAndValues...))
	}
}

// Info logs informational messages about the general state of the profiler.
// This is a wrapper around Infof for convenience.
func Info(msg string) {
	if getLogger().Enabled(context.Background(), slog.LevelInfo) {
		getLogger().Info(msg)
	}
}

// Errorf logs error messages about exceptional states of the profiler.
// This wrapper formats structured log data into a string message for
// backward compatibility with older unstructured logs.
func Errorf(msg string, keysAndValues ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelError) {
		getLogger().Error(fmt.Sprintf(msg, keysAndValues...))
	}
}

// Error logs error messages about exceptional states of the profiler.
// This is a wrapper around Errorf for convenience.
func Error(msg error) {
	if getLogger().Enabled(context.Background(), slog.LevelError) {
		getLogger().Error(msg.Error())
	}
}

// Debugf logs detailed debugging information about internal profiler behavior.
// This wrapper converts structured log data into a string message for
// backward compatibility with older unstructured logs.
func Debugf(msg string, keysAndValues ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelDebug) {
		getLogger().Debug(fmt.Sprintf(msg, keysAndValues...))
	}
}

// Debug logs detailed debugging information about internal profiler behavior.
// This is a wrapper around Debugf for convenience.
func Debug(msg string) {
	if getLogger().Enabled(context.Background(), slog.LevelDebug) {
		getLogger().Debug(msg)
	}
}

// Warnf logs warnings in the profiler — not errors, but likely more important
// than informational messages. This wrapper preserves backward compatibility
// by string-formatting structured log data.
func Warnf(msg string, keysAndValues ...any) {
	if getLogger().Enabled(context.Background(), slog.LevelWarn) {
		getLogger().Warn(fmt.Sprintf(msg, keysAndValues...))
	}
}

// Warn logs warnings in the profiler — not errors, but likely more important
// than informational messages. This is a wrapper around Warnf for convenience.
func Warn(msg string) {
	if getLogger().Enabled(context.Background(), slog.LevelWarn) {
		getLogger().Warn(msg)
	}
}

// leveledError wraps an error with the level it should be logged at. Producers use this
// to annotate an expected, non-actionable condition under which the operation safely
// degrades, so that log sites emit it below Error without each site re-deriving severity
// from the error's text.
type leveledError struct {
	level slog.Level
	err   error
}

func (e *leveledError) Error() string { return e.err.Error() }
func (e *leveledError) Unwrap() error { return e.err }

// WithLevel annotates err with the level it should be logged at when passed to Errore.
// Returns nil if err is nil.
//
// Use it only for expected, non-actionable conditions where the operation safely
// degrades — e.g. a recognized interpreter whose runtime version or architecture is not
// supported, where native unwinding is unaffected and only interpreter-level frames are
// missing. Do not use it to quiet a genuine failure (a read error, corrupt data, an eBPF
// map error); when in doubt, leave the error unannotated so it logs at Error.
func WithLevel(err error, level slog.Level) error {
	if err == nil {
		return nil
	}
	return &leveledError{level: level, err: err}
}

// Expected marks err as an expected, non-actionable condition, logged at Warn instead of
// Error. It is a convenience wrapper for WithLevel(err, slog.LevelWarn).
func Expected(err error) error {
	return WithLevel(err, slog.LevelWarn)
}

// LevelOf reports the level err should be logged at.
//
// An error annotated via WithLevel reports its annotated level. For a joined error
// (errors.Join), the maximum (most severe) level among its parts is reported, so a benign
// error joined with a genuine, unannotated one is never hidden. os.ErrNotExist defaults to
// Debug — very common if a process exited while it was being analyzed. Everything else
// defaults to Error, the safe default for an error nobody has classified.
func LevelOf(err error) slog.Level {
	if err == nil {
		return slog.LevelError
	}
	if le, ok := err.(*leveledError); ok { //nolint:errorlint
		return le.level
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok { //nolint:errorlint
		children := joined.Unwrap()
		if len(children) > 0 {
			level := slog.LevelDebug
			for _, child := range children {
				if l := LevelOf(child); l > level {
					level = l
				}
			}
			return level
		}
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok { //nolint:errorlint
		return LevelOf(wrapped.Unwrap())
	}
	if errors.Is(err, os.ErrNotExist) {
		return slog.LevelDebug
	}
	return slog.LevelError
}

// Errore logs err at LevelOf(err), formatting a context message the same way Errorf does.
// Use it at any log site that might receive an error annotated via WithLevel, so its
// requested severity is honored instead of always logging at Error.
func Errore(err error, format string, args ...any) {
	level := LevelOf(err)
	if getLogger().Enabled(context.Background(), level) {
		getLogger().Log(context.Background(), level, fmt.Sprintf(format, args...))
	}
}
