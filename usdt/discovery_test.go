// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/process"
)

func TestDiscoverReturnsCacheCopy(t *testing.T) {
	discoverer, err := NewDiscoverer()
	require.NoError(t, err)

	mapping := &process.RawMapping{
		Flags:  elf.PF_R | elf.PF_X,
		Device: 1,
		Inode:  2,
		Path:   "/usr/lib/libexample.so",
	}
	discoverer.parseCache.Add(mapping.GetOnDiskFileIdentifier(), []AttachmentPoint{{
		Provider: "provider",
		Name:     "probe",
		Location: 0x1234,
	}})

	points, err := discoverer.Discover(nil, mapping)
	require.NoError(t, err)
	require.Len(t, points, 1)
	points[0].Location = 0

	cached, err := discoverer.Discover(nil, mapping)
	require.NoError(t, err)
	require.Equal(t, uint64(0x1234), cached[0].Location)
}
