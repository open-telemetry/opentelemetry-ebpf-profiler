// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestValidateSystemAnalysisResult(t *testing.T) {
	address := libpf.SymbolValue(0x1234)

	t.Run("not handled", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Pid: 77}, address)
		require.Error(t, err)
		require.ErrorIs(t, err, errSystemAnalysisNotHandled)
		require.ErrorContains(t, err, "pid 77")
	})

	t.Run("helper failure", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Err: -14}, address)
		require.Error(t, err)
		require.True(t, errors.Is(err, errSystemAnalysisFailed))
		require.ErrorContains(t, err, "helper err=-14")
	})

	t.Run("success", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{}, address)
		require.NoError(t, err)
	})
}
