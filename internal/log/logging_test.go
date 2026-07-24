// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
)

// recordingHandler is a minimal slog.Handler that captures the level and formatted
// message of every record it receives, for asserting on Errore's chosen level.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func withRecordingLogger(t *testing.T) *recordingHandler {
	t.Helper()
	h := &recordingHandler{}
	prev := getLogger()
	SetLogger(*slog.New(h))
	t.Cleanup(func() { globalLogger.Store(prev) })
	return h
}

func TestLevelOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want slog.Level
	}{
		{"nil", nil, slog.LevelError},
		{"plain error", errors.New("boom"), slog.LevelError},
		{"expected", Expected(errors.New("unsupported Perl 5.26")), slog.LevelWarn},
		{"with level debug", WithLevel(errors.New("noisy"), slog.LevelDebug), slog.LevelDebug},
		{
			"wrapped expected (%w)",
			fmt.Errorf("failed to attach: %w", Expected(errors.New("unsupported"))),
			slog.LevelWarn,
		},
		{"os.ErrNotExist directly", os.ErrNotExist, slog.LevelDebug},
		{
			"wrapped os.ErrNotExist",
			fmt.Errorf("open x: %w", os.ErrNotExist),
			slog.LevelDebug,
		},
		{
			"joined: all expected -> max is warn",
			errors.Join(Expected(errors.New("a")), Expected(errors.New("b"))),
			slog.LevelWarn,
		},
		{
			"joined: benign + genuine -> error wins, never hidden",
			errors.Join(Expected(errors.New("benign")), errors.New("genuine failure")),
			slog.LevelError,
		},
		{
			"wrapped joined: benign + genuine -> still error",
			fmt.Errorf("errors occurred: %w",
				errors.Join(Expected(errors.New("benign")), errors.New("genuine failure"))),
			slog.LevelError,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LevelOf(c.err); got != c.want {
				t.Errorf("LevelOf(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestErrore(t *testing.T) {
	h := withRecordingLogger(t)

	Errore(Expected(errors.New("unsupported Perl 5.26.3 (need >= 5.28)")),
		"Failed to load %v: %v", "libperl.so", "unsupported Perl 5.26.3 (need >= 5.28)")
	Errore(errors.New("permission denied"), "Failed to load %v: %v", "x", "permission denied")

	if len(h.records) != 2 {
		t.Fatalf("got %d records, want 2", len(h.records))
	}
	if h.records[0].Level != slog.LevelWarn {
		t.Errorf("expected error logged at %v, got %v", slog.LevelWarn, h.records[0].Level)
	}
	if h.records[1].Level != slog.LevelError {
		t.Errorf("genuine error logged at %v, got %v", slog.LevelError, h.records[1].Level)
	}
}

func TestWithLevelNil(t *testing.T) {
	if err := WithLevel(nil, slog.LevelWarn); err != nil {
		t.Errorf("WithLevel(nil, ...) = %v, want nil", err)
	}
}
