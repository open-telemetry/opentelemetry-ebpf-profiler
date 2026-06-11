// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package vc provides buildtime information.
package vc // import "go.opentelemetry.io/ebpf-profiler/vc"

import (
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
)

var (
	// The following variables are going to be set at link time using ldflags
	// and can be referenced later in the program.

	// revision of the service
	revision = ""
	// buildTimestamp, timestamp of the build
	buildTimestamp = ""
	// version in vX.Y.Z{-N-abbrev} format (via git-describe --tags)
	version = ""

	buildInfoOnce sync.Once
	fallbackVC    struct {
		revision       string
		buildTimestamp string
		version        string
	}
	readBuildInfo = debug.ReadBuildInfo
)

const modulePath = "go.opentelemetry.io/ebpf-profiler"

// Revision of the service.
func Revision() string {
	loadBuildInfoFallback()
	if revision == "" {
		return fallbackVC.revision
	}
	return revision
}

// BuildTimestamp returns the timestamp of the build.
func BuildTimestamp() string {
	loadBuildInfoFallback()
	if buildTimestamp == "" {
		return fallbackVC.buildTimestamp
	}
	return buildTimestamp
}

// Version in vX.Y.Z{-N-abbrev} format.
func Version() string {
	loadBuildInfoFallback()
	if version == "" {
		return fallbackVC.version
	}
	return version
}

func loadBuildInfoFallback() {
	buildInfoOnce.Do(func() {
		buildInfo, ok := readBuildInfo()
		if !ok {
			return
		}

		selfModule := &buildInfo.Main
		if buildInfo.Main.Path != modulePath {
			if dep := findModule(buildInfo.Deps, modulePath); dep != nil {
				selfModule = dep
			}
		}

		if version := moduleVersion(selfModule); version != "" && version != "(devel)" {
			fallbackVC.version = version
		}

		if buildInfo.Main.Path == modulePath {
			for _, setting := range buildInfo.Settings {
				switch setting.Key {
				case "vcs.revision":
					fallbackVC.revision = setting.Value
				case "vcs.time":
					if t, err := time.Parse(time.RFC3339, setting.Value); err == nil {
						fallbackVC.buildTimestamp = strconv.FormatInt(t.Unix(), 10)
						continue
					}
					fallbackVC.buildTimestamp = setting.Value
				case "vcs.modified":
					if setting.Value == "true" && fallbackVC.version != "" &&
						!strings.Contains(fallbackVC.version, "dirty") {
						fallbackVC.version += "-dirty"
					}
				}
			}
		}

		fillFromPseudoVersion(fallbackVC.version)

		if fallbackVC.version == "" && fallbackVC.revision != "" {
			fallbackVC.version = "devel"
		}
	})
}

func findModule(modules []*debug.Module, path string) *debug.Module {
	for _, mod := range modules {
		if mod == nil {
			continue
		}
		if mod.Path == path {
			return mod
		}
	}
	return nil
}

func moduleVersion(mod *debug.Module) string {
	if mod == nil {
		return ""
	}
	if mod.Version != "" && mod.Version != "(devel)" {
		return mod.Version
	}
	if mod.Replace != nil && mod.Replace.Version != "" && mod.Replace.Version != "(devel)" {
		return mod.Replace.Version
	}
	return mod.Version
}

func fillFromPseudoVersion(version string) {
	if version == "" || !module.IsPseudoVersion(version) {
		return
	}

	if fallbackVC.revision == "" {
		if rev, err := module.PseudoVersionRev(version); err == nil {
			fallbackVC.revision = rev
		}
	}

	if fallbackVC.buildTimestamp == "" {
		if t, err := module.PseudoVersionTime(version); err == nil {
			fallbackVC.buildTimestamp = strconv.FormatInt(t.Unix(), 10)
		}
	}
}
