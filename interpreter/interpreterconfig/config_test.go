// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreterconfig

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoInterpreters(t *testing.T) {
	cfg := reflect.ValueOf(NoInterpreters())
	cfgType := cfg.Type()

	for i := range cfg.NumField() {
		field := cfg.Field(i)
		fieldType := cfgType.Field(i)

		interpreter, ok := field.Interface().(interface{ IsDisabled() bool })
		require.Truef(t, ok, "Config.%s does not implement IsDisabled", fieldType.Name)
		require.Truef(t, interpreter.IsDisabled(), "Config.%s is enabled", fieldType.Name)
	}
}
