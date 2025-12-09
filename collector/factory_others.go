// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"
)

func BuildProfilesReceiver(options ...Option) xreceiver.CreateProfilesFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		return nil, errors.New("profiling receiver is only supported on linux")

	}
}
