// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"runtime/debug"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFallsBackToBuildInfo(t *testing.T) {
	resetVCForTest(t)

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path:    modulePath,
				Version: "v1.2.3",
			},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef123456"},
				{Key: "vcs.time", Value: "2026-06-10T06:25:13Z"},
			},
		}, true
	}

	assert.Equal(t, "v1.2.3", Version())
	assert.Equal(t, "abcdef123456", Revision())
	assert.Equal(t, "1781072713", BuildTimestamp())
}

func TestLdflagsOverrideBuildInfoFallback(t *testing.T) {
	resetVCForTest(t)

	version = "v9.9.9"
	revision = "ldflags-revision"
	buildTimestamp = "123"
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path:    modulePath,
				Version: "v1.2.3",
			},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef123456"},
				{Key: "vcs.time", Value: "2026-06-10T06:25:13Z"},
			},
		}, true
	}

	assert.Equal(t, "v9.9.9", Version())
	assert.Equal(t, "ldflags-revision", Revision())
	assert.Equal(t, "123", BuildTimestamp())
}

func TestMarksFallbackVersionDirty(t *testing.T) {
	resetVCForTest(t)

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path:    modulePath,
				Version: "v1.2.3",
			},
			Settings: []debug.BuildSetting{
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}

	assert.Equal(t, "v1.2.3-dirty", Version())
}

func TestUsesDevelVersionWhenOnlyRevisionIsAvailable(t *testing.T) {
	resetVCForTest(t)

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path: modulePath,
			},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef123456"},
			},
		}, true
	}

	assert.Equal(t, "devel", Version())
	assert.Equal(t, "abcdef123456", Revision())
}

func TestFallsBackToDependencyBuildInfo(t *testing.T) {
	resetVCForTest(t)

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path:    "example.com/collector",
				Version: "v1.0.0",
			},
			Deps: []*debug.Module{
				{
					Path:    modulePath,
					Version: "v0.0.0-20260610062513-1aa2cb8c5f92",
				},
			},
		}, true
	}

	assert.Equal(t, "v0.0.0-20260610062513-1aa2cb8c5f92", Version())
	assert.Equal(t, "1aa2cb8c5f92", Revision())
	assert.Equal(t, "1781072713", BuildTimestamp())
}

func TestPrefersDependencyVersionOverLocalReplaceDevel(t *testing.T) {
	resetVCForTest(t)

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Path:    "example.com/collector",
				Version: "v1.0.0",
			},
			Deps: []*debug.Module{
				{
					Path:    modulePath,
					Version: "v0.0.0-20260610062513-1aa2cb8c5f92",
					Replace: &debug.Module{
						Path:    "/tmp/local-ebpf-profiler",
						Version: "(devel)",
					},
				},
			},
		}, true
	}

	assert.Equal(t, "v0.0.0-20260610062513-1aa2cb8c5f92", Version())
	assert.Equal(t, "1aa2cb8c5f92", Revision())
	assert.Equal(t, "1781072713", BuildTimestamp())
}

func resetVCForTest(t *testing.T) {
	t.Helper()

	originalVersion := version
	originalRevision := revision
	originalBuildTimestamp := buildTimestamp
	originalReadBuildInfo := readBuildInfo

	version = ""
	revision = ""
	buildTimestamp = ""
	buildInfoOnce = sync.Once{}
	fallbackVC = struct {
		revision       string
		buildTimestamp string
		version        string
	}{}
	readBuildInfo = debug.ReadBuildInfo

	t.Cleanup(func() {
		version = originalVersion
		revision = originalRevision
		buildTimestamp = originalBuildTimestamp
		readBuildInfo = originalReadBuildInfo
		buildInfoOnce = sync.Once{}
		fallbackVC = struct {
			revision       string
			buildTimestamp string
			version        string
		}{}
	})
}
