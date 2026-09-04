// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestDiscoverReturnsCacheCopy(t *testing.T) {
	discoverer, err := NewDiscoverer()
	require.NoError(t, err)

	fileID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	discoverer.parseCache.Add(fileID, []AttachmentPoint{{
		Provider: "provider",
		Name:     "probe",
		Location: 0x1234,
	}})

	// ref is unused because the cache hit returns before opening the ELF.
	ref := pfelf.NewReference("unused", nil)

	points, err := discoverer.Discover(ref, fileID)
	require.NoError(t, err)
	require.Len(t, points, 1)
	points[0].Location = 0

	cached, err := discoverer.Discover(ref, fileID)
	require.NoError(t, err)
	require.Equal(t, uint64(0x1234), cached[0].Location)
}
