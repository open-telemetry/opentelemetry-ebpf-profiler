// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
)

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		func() component.Config { return &struct{}{} },
		xreceiver.WithProfiles(BuildProfilesReceiver(), metadata.ProfilesStability))
}

func BuildProfilesReceiver(options ...Option) xreceiver.CreateProfilesFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		return nil, errors.New("profiling receiver is only supported on Linux and arm64 or amd64")
	}
}
